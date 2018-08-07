

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
/*fuzzSeed-209835301*/count=1; tryItOut("o0.v0 = Object.prototype.isPrototypeOf.call(b2, s0);");
/*fuzzSeed-209835301*/count=2; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((([] = (({ set __iterator__ setter (get = y, window, c = x, window = \u3056, z, a = new RegExp(\"(?=\\\\B)((?=\\u0013)+?)\", \"ym\"), b, x, a, a, y, x = z, x, x, NaN, x = true, b =  '' , x, x, a, \u3056, z, a = this, ...window) { yield /[^]/g } , y:  /x/g  }))) | 0) !== ((((Math.log2((( - y) | 0)) | 0) ? x : ( + Math.cos(( + -0x080000000)))) % ( + ((((new ( \"\" )( \"\" , /$+/gi) | 0) ? (Math.hypot(-Number.MAX_SAFE_INTEGER, (Math.sinh(y) >>> 0)) | 0) : (Math.ceil(x) | 0)) | 0) ** ( + ((0/0 >>> 0) * ( + Math.expm1((x >>> 0)))))))) | 0)) | 0); }); testMathyFunction(mathy3, [2**53, -(2**53+2), -Number.MAX_VALUE, -0x100000000, 0x080000001, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 1, -(2**53-2), -(2**53), 1.7976931348623157e308, -0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, 0x100000001, 0, 0x0ffffffff, 2**53-2, 42, -1/0, 2**53+2, -0x080000001, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, 1/0, 0x080000000]); ");
/*fuzzSeed-209835301*/count=3; tryItOut("\"use strict\"; throw x;");
/*fuzzSeed-209835301*/count=4; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n{} = x  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-((-4194303.0))));\n  }\n  return f; })(this, {ff: (new Function).call}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [2**53-2, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, -0x100000001, 0x100000001, 0x100000000, 2**53, 0x080000000, 1/0, -(2**53-2), -0x07fffffff, 1, 0, -(2**53+2), -0x080000001, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 1.7976931348623157e308, -1/0, -0, -Number.MAX_VALUE, Number.MIN_VALUE, 42, 0x080000001, 0/0]); ");
/*fuzzSeed-209835301*/count=5; tryItOut("(window);\n/*MXX2*/g2.ReferenceError.prototype = o2.b0;\n");
/*fuzzSeed-209835301*/count=6; tryItOut("mathy0 = (function(x, y) { return Math.abs(Math.imul(((Math.pow(Math.fround((Math.fround(x) >= (Math.fround(y) % ( - (( ! (y >>> 0)) >>> 0))))), Math.fround(( - (( + (Math.tan(Math.fround(x)) >>> 0)) << ( + y))))) >>> 0) >>> 0), (( - ((( + (( + Number.MAX_VALUE) ? ( + Math.pow(x, y)) : ( + x))) ? Math.fround((Math.sign(y) | 0)) : Math.fround(y)) | 0)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[true, true, NaN, e, (-1),  '' , e,  '' ,  '' , (-1), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, (-1), true,  '' ,  '' , NaN, (-1), e, (-1), (-1), e, NaN, true, e, true, true, true, true, NaN, NaN, e, (-1), true,  '' , true, e, e, e, (-1), (-1), (-1), NaN, NaN, e, true, true, (-1), true, (-1), NaN, NaN,  '' , NaN, e, (-1), NaN, true, true, true,  '' , true, NaN, e, (-1),  '' ,  '' , (-1),  '' , true,  '' , (-1), true, true, true,  '' , e, (-1)]); ");
/*fuzzSeed-209835301*/count=7; tryItOut("t2 = a1[10];");
/*fuzzSeed-209835301*/count=8; tryItOut("mathy1 = (function(x, y) { return ( ~ ( + ( + ( - ( + Math.abs(Math.fround(Math.pow(y, Math.fround(y))))))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 0x100000001, Math.PI, 0x0ffffffff, 1.7976931348623157e308, 0/0, 2**53-2, 0.000000000000001, -0x100000001, -0, -0x080000000, -0x0ffffffff, 0, -0x100000000, 2**53+2, 0x080000001, 42, 0x080000000, -0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 1/0, -(2**53-2), 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=9; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + Math.atan2(( + Math.expm1((( - x) | 0))), Math.fround(((Math.log2(y) >>> 0) !== ( + Math.atan2((((y !== (x >>> 0)) >>> 0) >>> 0), Math.imul(Math.fround(Math.cos(y)), x))))))) * (((y , ( ! Math.hypot(Math.fround((Math.min((y | 0), (-1/0 | 0)) | 0)), (( + (y | 0)) >>> 0)))) >>> 0) ** (Math.hypot(y, ( - x)) >>> 0))); }); testMathyFunction(mathy0, [-0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, 0x080000001, -0x100000001, -(2**53+2), 0/0, Number.MAX_VALUE, -(2**53-2), Math.PI, 0x0ffffffff, -0x080000000, 0x080000000, 2**53, -0x07fffffff, 1, -0, -1/0, 0x07fffffff, -0x100000000, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 2**53-2]); ");
/*fuzzSeed-209835301*/count=10; tryItOut("/*ODP-2*/Object.defineProperty(o0, \"revocable\", { configurable: [1,,], enumerable: false, get: (function() { try { Array.prototype.forEach.apply(a1, [(function() { this.o2.g1.h2.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var exp = stdlib.Math.exp;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+sqrt(((+(0.0/0.0))))));\n    d0 = (NaN);\n    d0 = (d1);\n    d0 = (+(-1.0/0.0));\n    d1 = (+((((((0xffffffff) % (0x0)) << ((((-0x8000000)) & ((0xffffffff))) / (~~(9.44473296573929e+21)))))-(0x3616c59e)) << ((((d0)))+((0x16099a45) < (0x0))+(1))));\n    d1 = (+((4277)));\n    {\n      d1 = (+pow(((let (window) null)), ((+(0xde7de259)))));\n    }\n    {\n      d0 = (d1);\n    }\n    d0 = (x);\nfor (var p in m0) { try { a0.shift(s2, e0, t2); } catch(e0) { } try { m0 = e0; } catch(e1) { } try { a0[12] = [[1]]; } catch(e2) { } g2.a1.forEach(); }    d0 = (d1);\n    d1 = (d0);\n    d0 = (d0);\n    return +((((Float64ArrayView[((0x9c8fb404)+((0x7ab21876) == (((0xdb126c3))>>>((0x37e092f))))-(0xff302929)) >> 3])) / ((Int16ArrayView[2]))));\n    d0 = (+exp(((d0))));\n    d1 = (d0);\n    d1 = (d1);\n    d1 = (d1);\n    {\n      {\n        (Int32ArrayView[(-(0xfc7df000)) >> 2]) = (((+(-1.0/0.0)) != (NaN))+(((((((+exp((((-2.4178516392292583e+24) + (4.835703278458517e+24)))))) % ((+(((0x79b209f0)) | ((0x9ca912b6)))))) == (+pow(((1.0)), ((d0)))))) >> (((0x6b0f2546) >= (((0xffb05538)-(0xf41745c8)) & ((0x99323cb3)+(0x72f64e32))))+(0x487ddef1)))));\n      }\n    }\n    return +((d0));\n  }\n  return f; }); return o0; })]); } catch(e0) { } try { g2.t2.set(t1, v2); } catch(e1) { } m1.set(e1, f1); return g1; }), set: (function() { /*RXUB*/var r = r0; var s = s1; print(r.exec(s));  return e1; }) });");
/*fuzzSeed-209835301*/count=11; tryItOut("\"use strict\"; g0.m0.has(h0);");
/*fuzzSeed-209835301*/count=12; tryItOut("v1 = evaluate(\"function f1(i0)  /x/ \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 3 != 2), sourceIsLazy: (x % 2 != 1), catchTermination: true, sourceMapURL: this.s1 }));function eval(x) /x/g  /x/ ;");
/*fuzzSeed-209835301*/count=13; tryItOut("print((4277));\nyield;\n");
/*fuzzSeed-209835301*/count=14; tryItOut("\"use strict\"; a = x;v1 = (m2 instanceof v0);");
/*fuzzSeed-209835301*/count=15; tryItOut("\"use strict\"; v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { try { this.v1 = this.o1.o0.o2.a1.every(/*wrap3*/(function(){ var sgetbh = x; (z => \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4611686018427388000.0;\n    var i3 = 0;\n    var d4 = 2305843009213694000.0;\n    d2 = (281474976710657.0);\n    return +((+pow(((d2)), ((((((Infinity)) / ((Float32ArrayView[4096])))) / ((1152921504606847000.0)))))));\n  }\n  return f;)(); }), o1.b1, z = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: q => q, delete: function() { throw 3; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })( /x/g ), function(y) { m1 = new WeakMap; }), this.b0); } catch(e0) { } try { m1.delete(v1); } catch(e1) { } try { 'fafafa'.replace(/a/g, \"\\uB52F\")/*\n*/; } catch(e2) { } g1.h2.defineProperty = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.9342813113834067e+25;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 4611686018427388000.0;\n    var i6 = 0;\n    var d7 = -268435457.0;\n    var i8 = 0;\n    {\n      return +((-1.0625));\n    }\n    {\n      i3 = (0xfc802752);\n    }\n    i3 = ((-0x8000000) < (((0xffda4c3d)) ^ (-((0xe70a5971) ? (i6) : (0xb776cf61)))));\n    d2 = (-36893488147419103000.0);\n    i3 = (0xf8999f7a);\n    switch ((~(((0x16b7cee0) != (0x7fd38734))-(i6)))) {\n      case -3:\n        (Float32ArrayView[((0xfcfc3668)+(0x9aabd68f)) >> 2]) = ((-4097.0));\n        break;\n      default:\n        i3 = ((!(i6)) ? (0xf854a39f) : (!(0xb8ff3347)));\n    }\n    i4 = (0x1d7a54b8);\n    return +((d7));\n  }\n  return f; }); return i0; })]);");
/*fuzzSeed-209835301*/count=16; tryItOut("/*bLoop*/for (xqzadu = 0; xqzadu < 10; (e = ((p={}, (p.z = [])()))), ++xqzadu) { if (xqzadu % 4 == 2) { p2.__proto__ = a2; } else { a1.shift(p2); }  } ");
/*fuzzSeed-209835301*/count=17; tryItOut("(((TypeError.prototype.toString).call((void shapeOf( /x/ )), x,  \"\" )));");
/*fuzzSeed-209835301*/count=18; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.imul((mathy2(((Math.fround(y) + ( ! (((y >>> 0) ? (0.000000000000001 >>> 0) : Math.fround(y)) >>> 0))) >>> 0), (mathy2(( + ( - ( + x))), ( + x)) | 0)) | 0), ( + Math.atan2(y, x))) | 0) < Math.clz32(Math.fround(( + Math.fround(x))))) | 0); }); ");
/*fuzzSeed-209835301*/count=19; tryItOut("( /x/ );v0 = evalcx(\"\", g0);");
/*fuzzSeed-209835301*/count=20; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.atan2(Math.ceil(Math.acosh(x)), (Math.fround((Math.fround(x) & y)) ? Math.acos((( + Math.log2(Math.cosh(mathy0(y, -Number.MAX_SAFE_INTEGER)))) >>> 0)) : (( + ( - ( + ( + Math.imul((Math.imul(1.7976931348623157e308, 0x080000000) | 0), Math.imul(0x100000000, -Number.MIN_SAFE_INTEGER)))))) >>> 0))); }); testMathyFunction(mathy3, [-(2**53+2), 0/0, 1/0, -0x0ffffffff, 1.7976931348623157e308, 0x080000000, -0x07fffffff, 0.000000000000001, 42, 1, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, -0x080000000, -Number.MIN_VALUE, -0x100000001, 2**53+2, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53, -(2**53), 0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, -1/0, 0, -Number.MAX_VALUE, Math.PI, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, 0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=21; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.atanh((Math.fround(Math.sinh((mathy0((Math.imul(((x ^ -Number.MIN_SAFE_INTEGER) >>> 0), (Math.fround((Math.fround(mathy0(Math.fround(y), Math.fround(y))) | Math.fround(y))) >>> 0)) >>> 0), (Math.asinh(( + mathy0(Math.PI, (2**53 | 0)))) * Math.fround((x < ( ! x))))) >>> 0))) | 0)); }); testMathyFunction(mathy1, [false, 0.1, (new Number(-0)), '/0/', /0/, '\\0', null, [0], (new Number(0)), (new Boolean(true)), undefined, (new String('')), ({toString:function(){return '0';}}), true, 0, NaN, ({valueOf:function(){return 0;}}), (new Boolean(false)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), [], '0', -0, 1, '', (function(){return 0;})]); ");
/*fuzzSeed-209835301*/count=22; tryItOut("h1.keys = f1;");
/*fuzzSeed-209835301*/count=23; tryItOut("\"use strict\"; { void 0; verifyprebarriers(); } o0.v2 = evaluate(\"i1 + m1;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: true, elementAttributeName: s0 }));");
/*fuzzSeed-209835301*/count=24; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return (mathy0(Math.sin(Math.fround((((Math.pow(Math.fround(( + x)), (Math.min((x | 0), ( + -1/0)) | 0)) >>> 0) && ((Math.imul(( + ( + 0.000000000000001)), y) >> y) >>> 0)) >>> 0))), (((Math.fround(Math.pow(( + ((x | 0) >= (y | 0))), (Math.asin((( ! Math.fround(Math.atan2((x >>> 0), Math.fround(-0x080000000)))) | 0)) | 0))) ? (y ? y : (y || x)) : Math.hypot((( + Math.abs(( + ( + ( + Math.clz32(( + y))))))) | 0), y)) | 0) | 0)) | 0); }); ");
/*fuzzSeed-209835301*/count=25; tryItOut("m2.set(v0, t1);");
/*fuzzSeed-209835301*/count=26; tryItOut("\"use strict\"; for(var x in ((\"\\uE38C\")( '' )))/*RXUB*/var r = r2; var s = s1; print(uneval(s.match(r))); let x = x;");
/*fuzzSeed-209835301*/count=27; tryItOut("i2.send(t0);");
/*fuzzSeed-209835301*/count=28; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.acos(( + Math.hypot(( ~ 0), (( + Math.fround((Math.fround(0.000000000000001) ** Math.fround(Math.atan2(y, Math.log2(x)))))) ? ((Math.round((Math.min((y | 0), (x | 0)) | 0)) | 0) & ( + Math.cbrt((x >>> 0)))) : Math.fround((Math.fround((Math.imul(x, ( + x)) >>> 0)) > (Math.imul(0x07fffffff, ( + ( + x))) >>> 0))))))); }); testMathyFunction(mathy0, [0x080000001, -0x080000001, -(2**53), 0x0ffffffff, 0x100000000, -0x07fffffff, 2**53, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, 0/0, 42, 1/0, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, Number.MAX_SAFE_INTEGER, -0, -(2**53+2), -(2**53-2), 2**53+2, 2**53-2, -0x100000000, Number.MAX_VALUE, -1/0, 1, Math.PI, -0x080000000]); ");
/*fuzzSeed-209835301*/count=29; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.max(Math.pow(Math.pow(( + Math.ceil(y)), ( ~ (( + y) / y))), Math.fround((Math.fround(( + ( + Math.imul((Math.atanh(y) >>> 0), Math.fround(Math.clz32(Math.sqrt(x))))))) === Math.fround(x)))), Math.hypot((( ~ ((Math.pow((x | 0), (y | 0)) | 0) >>> 0)) >>> 0), Math.max(Math.fround(Math.imul(x, Math.fround(((Math.fround(y) ? x : x) ? ( + y) : x)))), (y | 0)))); }); ");
/*fuzzSeed-209835301*/count=30; tryItOut("if(false) { if (x) h0.keys = f1;} else print(x);");
/*fuzzSeed-209835301*/count=31; tryItOut("mathy3 = (function(x, y) { return Math.min((Math.log1p((((( ~ (y | 0)) | 0) ? Math.trunc(y) : ( ! Math.fround((x ? x : y)))) >>> 0)) >>> 0), mathy1(((Math.imul((-0x07fffffff | 0), (y | 0)) | 0) ? y : (Math.max((( ~ (x >>> 0)) >>> 0), y) >>> 0)), (((Math.fround(Math.hypot(Math.fround(x), (-0x07fffffff >>> 0))) | 0) == (y | 0)) | 0))); }); testMathyFunction(mathy3, [-(2**53), 2**53-2, 0, -1/0, -0x080000000, 0x080000001, 0x07fffffff, 2**53+2, 0x100000000, -0x080000001, 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -0, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, 0x080000000, 2**53, Math.PI, -(2**53-2), 1, 0/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 42, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=32; tryItOut("(false);");
/*fuzzSeed-209835301*/count=33; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! (Math.fround((( + (( + (Math.hypot(((Math.asinh((x >>> 0)) >>> 0) | 0), (y | 0)) | 0)) ? ( + ( + ((( - x) << y) * x))) : -(2**53+2))) == Math.fround(Math.exp(x)))) >>> 0)); }); testMathyFunction(mathy4, [0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, 0.000000000000001, 42, -0x0ffffffff, -0x080000001, -(2**53+2), -(2**53), -1/0, 2**53, 1.7976931348623157e308, Math.PI, -(2**53-2), 2**53-2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0/0, 1, -0x100000000, 0x080000000, Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 1/0, 0x0ffffffff, -0x080000000, -0]); ");
/*fuzzSeed-209835301*/count=34; tryItOut("for(let d in (4277) for (z in x)) try { b.message; } catch(c if (function(){yield let (e =  \"\" ) e;})()) { return; } catch(z if (function(){let(horasi, NaN = (yield window in /.*?/gyi.__defineSetter__(\"d\", Math.min)), ftvhly, qdjfnz, d, aioopb, uwqglz) { yield /*UUV1*/(d.set = decodeURIComponent);}})()) { c = x; } o0.b1 = t2.buffer;");
/*fuzzSeed-209835301*/count=35; tryItOut("/*vLoop*/for (var ovveeq = 0; ovveeq < 41; ++ovveeq) { const w = ovveeq; /*MXX1*/o2 = g2.Date.prototype.toGMTString; } ");
/*fuzzSeed-209835301*/count=36; tryItOut("\"use strict\"; o0.o2.t0[({a1:1})] = \"\\uD63D\";");
/*fuzzSeed-209835301*/count=37; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2*?|[\\\\cL-\\\\\\u0087\\u00d4-\\\\f$-\\\\u00F7\\\\u0073]\", \"gyim\"); var s = \"\\ns\"; print(s.search(r)); ");
/*fuzzSeed-209835301*/count=38; tryItOut("for (var v of g0) { try { Object.defineProperty(this, \"v0\", { configurable: false, enumerable: (x % 14 == 3),  get: function() {  return t0.length; } }); } catch(e0) { } a0.sort((function mcc_() { var nzjwsj = 0; return function() { ++nzjwsj; f2(/*ICCD*/nzjwsj % 7 == 6);};})(), g0, g2.e1, t1, f1); }s0 += 'x';\na2.forEach((function(j) { if (j) { try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e0) { } try { s1 = ''; } catch(e1) { } a1.push(o0.i1); } else { a2 = o0.a2.concat(a0, t2, o2.f1, t2); } }), p0);\n");
/*fuzzSeed-209835301*/count=39; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.log1p(( + ( + ((Math.acosh(Math.sinh(( + Math.acosh((y >>> 0))))) >>> 0) >>> ( + Math.max((x | 0), Math.fround(Math.acos(((Math.fround(y) >= Math.fround(( + (Math.fround(x) ? Math.PI : ( + y))))) >>> 0))))))))), Math.cos(Math.sqrt((((Math.min(( - y), (Math.fround(Math.acosh(-(2**53+2))) >>> 0)) >>> 0) ? (( ! Math.fround(Math.fround(Math.fround((( ! y) | 0))))) >>> 0) : ((( - ( + Math.hypot(y, -0x0ffffffff))) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [-0x080000001, 42, -0x100000000, 2**53-2, -0x080000000, 0, 0x07fffffff, 1, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x07fffffff, 2**53+2, 0x0ffffffff, 0x080000001, Math.PI, -1/0, 2**53, -(2**53+2), 0x100000000, 0/0, -0x100000001]); ");
/*fuzzSeed-209835301*/count=40; tryItOut("Array.prototype.splice.call(g1.g1.a0, NaN, 4);");
/*fuzzSeed-209835301*/count=41; tryItOut("mathy3 = (function(x, y) { return ( ! ((y ^ Math.hypot(x, ( + (( + y) === y)))) ? Math.fround((Math.fround(mathy1(y, Math.atan2(x, x))) ? Math.fround(Math.trunc(Math.fround(0.000000000000001))) : ( + x))) : (Math.hypot((Math.min((x + y), -Number.MIN_VALUE) >>> 0), (Math.PI || (mathy1(0x080000000, x) | 0))) >= (( + (((Math.log(Math.fround(y)) | 0) >>> 0) <= mathy1(x, Math.fround(x)))) ** Math.min(( + y), -0x100000001))))); }); testMathyFunction(mathy3, [0x0ffffffff, -0x080000001, Math.PI, 0x100000001, 1, -0, 42, 0/0, -0x080000000, -0x100000000, -0x07fffffff, Number.MAX_VALUE, 0, -(2**53), Number.MIN_VALUE, -(2**53+2), 0x07fffffff, -(2**53-2), 1/0, 0x080000001, 0.000000000000001, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 2**53-2, -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=42; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( - Math.atanh(( ! (y | 0))))); }); ");
/*fuzzSeed-209835301*/count=43; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-1.0009765625);\n    (Uint32ArrayView[4096]) = (((((i1)-(eval(\"\\\"use strict\\\"; Array.prototype.sort.apply(a0, [f2, b2, f0, e2, window, f0]);\", x = \nx))) & ((i1)*0xe7000)) <= (0x38e41d4e)));\n    (Float64ArrayView[((/*FFI*/ff(((((d0)) % ((Float32ArrayView[1])))), (((9.44473296573929e+21) + (1.5474250491067253e+26))), ((((-0x8000000)) & ((0xd335d789)))))|0)-((((0x6cd6974c)) ^ ((0x8df7ed52))) <= (((0xfddc1ed3)) ^ ((0xd7e05290))))-(0x23d0b64a)) >> 3]) = ((NaN));\n    (Uint16ArrayView[((0xfbc68d31)) >> 1]) = ((((-0xfffff*(/*FFI*/ff(((+((-((((-262143.0) + (17.0)) + (-1152921504606847000.0))))))), ((((0x9067755b)) >> (((4277))+((0x10b7a819))))), ((6.189700196426902e+26)), ((((0xffffffff)) | ((-0x8000000)))), ((-((3.022314549036573e+23)))), ((-3.777893186295716e+22)), ((1.1805916207174113e+21)), ((-295147905179352830000.0)), ((257.0)))|0))>>>(((-0x2c1d8*((0x38bb3ade) ? (0xeb9b7591) : (0x1811aeb7)))>>>((0xfbc3c1e7)+((3.094850098213451e+26) <= (1.9342813113834067e+25)))) / (0xffffffff)))));\n    d0 = (+(1.0/0.0));\n    (Int8ArrayView[1]) = ((0x2ff2a9f));\n    return (((timeout(1800)) % (((new RegExp(\"\\\\3\", \"m\"))(\"\\u7297\") = c))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.round((Math.max((y | 0), (x - (y >>> 0))) | 0)); })}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, -0, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, 0x0ffffffff, -(2**53), 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), 0/0, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x07fffffff, 0, 1/0, 0x07fffffff, 1, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -(2**53-2), Math.PI, 2**53, -0x080000001, 2**53-2]); ");
/*fuzzSeed-209835301*/count=44; tryItOut("\"use strict\"; v2 = (e0 instanceof o2.o2);");
/*fuzzSeed-209835301*/count=45; tryItOut("\"use asm\"; /*tLoop*/for (let b of /*MARR*/[]) { var gzwxep = new ArrayBuffer(8); var gzwxep_0 = new Float64Array(gzwxep); gzwxep_0[0] = 5; new RegExp(\"\\\\2\", \"g\"); }");
/*fuzzSeed-209835301*/count=46; tryItOut("s0 += 'x';");
/*fuzzSeed-209835301*/count=47; tryItOut("\"use strict\"; print(undefined >> false);\nprint(-11\n);\n");
/*fuzzSeed-209835301*/count=48; tryItOut("mathy0 = (function(x, y) { return (Math.cbrt(((void options('strict_mode')) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-1/0, -Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -0x080000001, 0x100000001, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, -0x100000001, Number.MAX_VALUE, 0/0, Math.PI, -0, -(2**53+2), 0, 0x080000000, -0x07fffffff, -(2**53), 2**53-2, Number.MIN_VALUE, -0x100000000, 0x07fffffff, 0x0ffffffff, 0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -(2**53-2), 1/0]); ");
/*fuzzSeed-209835301*/count=49; tryItOut("c = this.d;x = x;");
/*fuzzSeed-209835301*/count=50; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((Math.atan2(( ~ ( - x)), mathy2(( + Math.atan2(Math.sinh(mathy1(( ! x), (-(2**53) | 0))), 0/0)), Math.fround(mathy1(x, (Math.min(-(2**53+2), x) === mathy0(x, x)))))) | 0) - (( ~ ( + ( + ( + ((0/0 !== Math.fround(x)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [-0x100000000, 42, 1.7976931348623157e308, -(2**53), -0x07fffffff, -0x080000001, Number.MAX_VALUE, 0x07fffffff, -0x080000000, 2**53-2, -(2**53+2), 0/0, 0, 0x0ffffffff, 2**53+2, 0.000000000000001, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x0ffffffff, 1, -0, -1/0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x080000000]); ");
/*fuzzSeed-209835301*/count=51; tryItOut("testMathyFunction(mathy0, [0x07fffffff, -0x07fffffff, 42, 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -0x080000001, Math.PI, 2**53+2, -0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, 0x0ffffffff, -0x100000001, -(2**53-2), 0x080000001, 0/0, 0, -(2**53), -1/0, -Number.MAX_VALUE, 2**53-2, 1/0, -(2**53+2), 1, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=52; tryItOut("mathy3 = (function(x, y) { return (mathy2(Math.fround((Math.fround(((Math.max(Math.max(y, 2**53+2), ( + Math.hypot(( + Number.MIN_VALUE), y))) >> ((mathy1((y | 0), (Math.cosh(x) | 0)) | 0) | 0)) | 0)) <= Math.fround(x))), ((Math.acos(Math.fround(Math.tanh(( ! Math.atan2(Math.PI, Math.fround(y)))))) & y) | 0)) | ( ~ ( + (( - (mathy2((( + y) >>> 0), ( + (( + y) ? ( + x) : ( + 0/0)))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-209835301*/count=53; tryItOut("o2 = x;");
/*fuzzSeed-209835301*/count=54; tryItOut("this.e2.has(g0);");
/*fuzzSeed-209835301*/count=55; tryItOut("v0 = (this.m0 instanceof o1);");
/*fuzzSeed-209835301*/count=56; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=57; tryItOut("/*RXUB*/var r = /((?!(?!(?!\\B\\cV|\\s$*?).)))/ym; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=58; tryItOut("var tnwkvq = new ArrayBuffer(0); var tnwkvq_0 = new Uint8Array(tnwkvq); print(tnwkvq_0[0]); var tnwkvq_1 = new Int32Array(tnwkvq); tnwkvq_1[0] = -2; var tnwkvq_2 = new Uint8Array(tnwkvq); print(tnwkvq_2[0]); var tnwkvq_3 = new Uint8Array(tnwkvq); print(tnwkvq_3[0]); tnwkvq_3[0] = 15; /* no regression tests found */this.e0.add(t2);e0 + '';Array.prototype.shift.apply(a0, [v0, o0]);(void schedulegc(this.g2));(4277);with({x: tnwkvq_1[2]|=b = Proxy.createFunction(({/*TOODEEP*/})(tnwkvq_0[0]), \"\\u32C4\", function (e)[z1])}){g0.p0 = t2[1];a1 = new Array; }");
/*fuzzSeed-209835301*/count=59; tryItOut("mathy3 = (function(x, y) { return (Math.sqrt(Math.atan(( ! (Math.fround(( ~ (y >>> 0))) >>> 0)))) || Math.asin((mathy2(( + ( + Math.atan2((Math.atan(y) >>> 0), (( + (( + Math.acosh(x)) <= ( + 2**53-2))) | 0)))), ( + Math.fround(( + x)))) | 0))); }); testMathyFunction(mathy3, [0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53, 0x100000001, -0, -0x080000000, -0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000001, -0x0ffffffff, -0x100000001, 0x080000000, Math.PI, -(2**53), 42, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, 0x07fffffff, -0x100000000, 1, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), -Number.MAX_VALUE, -1/0, 2**53+2, 0x100000000, 2**53-2, Number.MIN_VALUE, 0/0, 1/0]); ");
/*fuzzSeed-209835301*/count=60; tryItOut("\"use strict\"; p2 = m2.get(v1);");
/*fuzzSeed-209835301*/count=61; tryItOut(";");
/*fuzzSeed-209835301*/count=62; tryItOut("\"use strict\"; a1[0] = s0;");
/*fuzzSeed-209835301*/count=63; tryItOut("mathy2 = (function(x, y) { return ((mathy0(Math.fround(((Math.asinh(Math.fround((1 ? -0 : x))) * y) >> x)), Math.tan(Math.max(Math.fround((y ^ 42)), Math.max(-1/0, x)))) | 0) % Math.fround(( - ((( ~ ((((Math.max(x, (Math.round(x) | 0)) | 0) >>> 0) | x) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), function(){}, function(){}, new String('q'), new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), function(){}, function(){}, function(){}, new String('q'), function(){}, function(){}, new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), function(){}, new String('q'), function(){}, function(){}, new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-209835301*/count=64; tryItOut("/*oLoop*/for (var kmvfee = 0; kmvfee < 42; ++kmvfee, (4277)) { f2 + v2; } ");
/*fuzzSeed-209835301*/count=65; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=66; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((((x >>> 0) !== Math.abs(( + mathy0(x, (y ? x : x))))) >>> 0) >>> 0) !== (mathy0(x, y) - (x >>> 0))) && ( ~ ( + mathy0(Math.imul((mathy0(((y ? -Number.MAX_VALUE : (y >>> 0)) | 0), Math.fround(mathy0(Math.fround(-0), Math.fround(-0x100000001)))) | 0), y), Math.fround(Math.max(-0x0ffffffff, (((mathy0(((y >> x) | 0), (-0x080000001 | 0)) >>> 0) > 42) | 0))))))); }); testMathyFunction(mathy1, [42, Number.MAX_VALUE, -1/0, 2**53, Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, -0x07fffffff, Math.PI, 1/0, -0x100000000, -0x080000001, 0x07fffffff, 0x0ffffffff, 0x080000001, -(2**53), -0, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, 0/0, 0.000000000000001, -Number.MAX_VALUE, 0x100000000, 2**53-2, 2**53+2, -(2**53+2), -0x100000001]); ");
/*fuzzSeed-209835301*/count=67; tryItOut("Date.prototype = NaN;o1.t2.__proto__ = p2;");
/*fuzzSeed-209835301*/count=68; tryItOut("/*oLoop*/for (var upwtpv = 0; upwtpv < 113; ++upwtpv) { print(NaN); } ");
/*fuzzSeed-209835301*/count=69; tryItOut("Array.prototype.pop.apply(a1, [o2, this.f1]);");
/*fuzzSeed-209835301*/count=70; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy1((Math.exp(Math.atanh((((Math.pow(Math.min(( + y), (0 | 0)), y) >>> 0) % (( - ( - x)) >>> 0)) >>> 0))) >>> 0), Math.fround((Math.fround(Math.fround(Math.ceil(Math.fround((mathy1(Math.fround((y ** y)), Math.fround(Math.min(x, (Math.min((1.7976931348623157e308 | 0), y) | 0)))) ? ((((mathy1((Math.cbrt(-0x07fffffff) >>> 0), (x >>> 0)) >>> 0) | 0) !== (-0x07fffffff | 0)) | 0) : ( ! x)))))) !== Math.fround(( ! ( ! Math.fround(Math.acosh(Math.fround(-Number.MIN_VALUE))))))))); }); testMathyFunction(mathy4, [-(2**53-2), 42, -0x080000001, -1/0, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), 0, 0x07fffffff, 0x0ffffffff, Math.PI, 0/0, -0x080000000, 1, -Number.MIN_VALUE, -0x07fffffff, -(2**53), 0x080000000, 0x100000000, 2**53-2, -0x0ffffffff, 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53, 1.7976931348623157e308, -0, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, 0x100000001]); ");
/*fuzzSeed-209835301*/count=71; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( - ( + (Math.fround(((( ! Math.fround(mathy1((x | 0), y))) >>> 0) | ( + x))) == (( ~ (Math.hypot((Math.fround(( ~ Math.fround((Math.pow(y, (-0x080000000 | 0)) | 0)))) | 0), ((Math.imul(( + (Math.fround(( + y)) === y)), Math.abs(y)) >>> 0) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy5, [-0x100000000, Number.MAX_VALUE, 42, 2**53+2, 1, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x100000001, 0, 0x080000000, -(2**53+2), 0/0, 1.7976931348623157e308, -0x100000001, -(2**53), 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, 2**53, 1/0]); ");
/*fuzzSeed-209835301*/count=72; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 590295810358705700000.0;\n    var d3 = -7.555786372591432e+22;\n    {\n      return (((0xffffffff)+(0xabd87d09)))|0;\n    }\n    return (((0xffffffff)-(0xfb47c7de)))|0;\n    i1 = (((((((0xf0287fe) / (((0xb61ba434)) | ((-0x8000000)))) << ((Uint16ArrayView[((0x42592587)*-0xf9faa) >> 1]))))) >> (((((0x2b5f32c8)-((0xa849e22) ? (0xbd8c6a4c) : (0xffffffff)))>>>((0xb7b25f20)-(0x384781dd)))))) == (0x572800ca));\n    d2 = (+abs(((+(((((0xdc841869)-(0xaa28e061)-(0x5acdc8af))>>>((-0x8000000)+(0xbc926434)-(0xffa2269a))) % (0x3afe7db1)) >> ((0x2f95726)))))));\n    d0 = (+abs(((d0))));\n    {\n      (Float64ArrayView[1]) = ((d0));\n    }\n    {\n      d0 = (d2);\n    }\n    (Float32ArrayView[1]) = ((+(0.0/0.0)));\n    d3 = (d0);\n    return (((0x276868a9) % (((0x291e81b8)+(0x3c178f1a))>>>(-0x5b521*(/*MARR*/[new Number(1.5), function(){}, ({x:3}), function(){}, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), function(){}, new Number(1.5), ({x:3}), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), new Number(1.5), new Number(1.5), function(){}, function(){}, new Number(1.5), ({x:3}), new Number(1.5), function(){}, new Number(1.5), ({x:3}), ({x:3}), new Number(1.5), ({x:3}), function(){}, ({x:3}), ({x:3}), ({x:3}), new Number(1.5), new Number(1.5), ({x:3}), function(){}, new Number(1.5), function(){}, new Number(1.5), ({x:3}), function(){}].some((4277)))))))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [0x100000001, -0, 1, 0x100000000, 0, -1/0, 0x0ffffffff, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 0.000000000000001, 0x080000000, 42, -0x07fffffff, -Number.MIN_VALUE, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 2**53-2, -0x100000001, 0x080000001, 2**53]); ");
/*fuzzSeed-209835301*/count=73; tryItOut("h2.iterate = (function(j) { if (j) { try { Array.prototype.sort.call(o2.a2, (function() { try { v0 = (m1 instanceof t2); } catch(e0) { } var r0 = new RegExp(\"(?:\\\\B{2,8589934594})*?\", \"gi\"); return s2; }), i2); } catch(e0) { } try { m0.has(g1.g0.o1.m0); } catch(e1) { } try { v1 = a1.length; } catch(e2) { } m0.has(p2); } else { try { m1.get(o2); } catch(e0) { } e2.add(g0.i0); } });");
/*fuzzSeed-209835301*/count=74; tryItOut("mathy5 = (function(x, y) { return (Math.hypot(Math.fround(mathy3(Math.fround(( + (Math.cosh(( + (y == y))) | 0))), Math.fround(mathy1(mathy1(( ~ (y > Math.PI)), y), (( + Math.sin(x)) >>> 0))))), Math.sin(Math.max(Math.fround(Math.fround(mathy2(Math.fround(-0x07fffffff), Math.fround(0x100000000)))), (Math.fround((( + mathy4((-0x0ffffffff >>> 0), (y >>> 0))) ** ( + (( ~ ( + x)) | 0)))) | 0)))) != ((Math.max(( - x), Math.fround(((Math.pow(x, Math.hypot(-0x080000000, y)) >>> 0) * Math.fround(x)))) | 0) ? ( ~ ( + Math.pow(( + y), (Math.trunc(( - (y >>> 0))) >>> 0)))) : ( + ( + Math.clz32(( + ( ! y))))))); }); testMathyFunction(mathy5, [0x100000001, 2**53-2, -0x100000000, 1, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, Math.PI, -0x080000001, 2**53+2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -1/0, 0, -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0x100000000, -Number.MIN_VALUE, -0, 0/0, 0.000000000000001, 0x0ffffffff, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, 42, -0x080000000, -(2**53), 0x080000000]); ");
/*fuzzSeed-209835301*/count=75; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=76; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + (( + (( + (0x080000000 > Math.asinh((Math.atan2((-Number.MAX_SAFE_INTEGER >>> 0), (( ! (y >>> 0)) >>> 0)) >>> 0)))) | (Math.asinh((((Math.pow(x, -0x080000001) >>> 0) !== (y >>> 0)) | 0)) >>> 0))) | 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x080000000, -(2**53-2), 0x100000000, 1/0, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), 42, Math.PI, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0/0, Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, 0.000000000000001, -0, 2**53-2, 0x080000000, -1/0, 1, 0x0ffffffff, -(2**53+2), 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=77; tryItOut("\"use strict\"; print(v2);");
/*fuzzSeed-209835301*/count=78; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( ~ ( + ((mathy4(42, Math.fround(Math.round(y))) - Math.min(Math.imul(1.7976931348623157e308, y), ( - Math.fround(Math.sinh(Math.fround(((y + (x | 0)) >>> 0))))))) | 0))) | 0); }); ");
/*fuzzSeed-209835301*/count=79; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.exp(Math.hypot(( - y), ( + ((x % (Math.fround(Math.pow(x, x)) | 0)) | 0)))); }); testMathyFunction(mathy2, /*MARR*/[['z'], new String('q'), x, new String('q'), new String('q'), true, true, x, ['z'], true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, x, new String('q'), new String('q'), x, ['z'], ['z'], new String('q'), new String('q'), x, true, ['z'], x, x, new String('q'), ['z'], ['z'], true, x, true, true, x, x, x, new String('q'), true, x, x, new String('q'), true, new String('q'), ['z'], x, x, new String('q'), true, true, ['z'], true, new String('q'), new String('q'), ['z'], new String('q'), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z']]); ");
/*fuzzSeed-209835301*/count=80; tryItOut("/*oLoop*/for (let gtgdan = 0; gtgdan < 6 && ( \"\" ); ++gtgdan) { (undefined); } ");
/*fuzzSeed-209835301*/count=81; tryItOut("");
/*fuzzSeed-209835301*/count=82; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.fround((Math.pow(Math.imul(y, (((y >>> 0) & (y >>> 0)) >>> 0)), ((Math.acosh(( + x)) * x) | 0)) === (0 === Math.max(Math.log(( - 1)), ( + Math.sqrt(y))))))) <= Math.fround((Math.min(Math.fround((Math.fround(y) | Math.fround(y))), (x <= Math.fround(( + ( ! x))))) === ((Math.tan(Math.min(y, 0x0ffffffff)) > y) >>> 0))))); }); testMathyFunction(mathy0, [0, -0x080000001, Number.MIN_VALUE, 0x080000000, 0x080000001, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 0x100000001, -0x100000000, -Number.MAX_VALUE, 2**53+2, 1/0, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, -(2**53+2), 0x100000000, -0x100000001, 1.7976931348623157e308, -0x0ffffffff, 1, 2**53, -0x080000000, 2**53-2, 0x0ffffffff, Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=83; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(( ! Math.max(y, 1.7976931348623157e308))) - Math.min(Math.fround(mathy2(Math.imul((mathy0(( + Math.fround(mathy4(x, Math.fround(y)))), ( ! Math.fround(x))) | 0), Math.log(0x100000001)), (( + Math.imul(Math.fround(( + Math.atan(x))), x)) | 0))), (y & (Math.max(Math.fround(Math.PI), x) | 0)))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, -0x080000001, -1/0, -Number.MAX_VALUE, -(2**53+2), 2**53+2, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, 1, 0x080000001, 1.7976931348623157e308, -0x100000000, -(2**53-2), 0.000000000000001, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, -(2**53), -0x080000000, 42, -Number.MIN_SAFE_INTEGER, -0, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=84; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=85; tryItOut("g2.offThreadCompileScript(\"for (var p in e0) { try { m2 = new Map; } catch(e0) { } /*RXUB*/var r = r2; var s = \\\"\\\"; print(s.match(r));  }\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 == 0), noScriptRval: b = [ \"\" ], sourceIsLazy: (x % 33 != 25), catchTermination: false }));");
/*fuzzSeed-209835301*/count=86; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-209835301*/count=87; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.max(((((Math.max(mathy2((Math.fround(( + ( + ( ! y)))) | 0), x), Math.sinh(Math.fround(( - x)))) | 0) < ((Math.max((Math.atan2(Math.fround(( ! ( ! Math.fround(Math.max(x, y))))), Math.cos((Math.fround(( - Math.fround(x))) | 0))) | 0), Math.fround(Math.imul(Math.fround(x), (Math.sinh(Math.fround(x)) | 0)))) >>> 0) | 0)) | 0) | 0), ((mathy0(((( ~ (( - ( ! (y ? x : -Number.MIN_VALUE))) | 0)) | 0) | 0), ((mathy3((x | 0), (( + Math.min((( ~ y) | 0), mathy0(-0x080000000, x))) | 0)) | 0) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy5, [-(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -0x080000001, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0x100000001, -(2**53), -0, -0x100000001, 0x0ffffffff, 1, 42, 1/0, 0x080000000, 1.7976931348623157e308, 0x100000000, 2**53-2, -0x080000000, 0.000000000000001, 2**53, -1/0, 0, 0x080000001]); ");
/*fuzzSeed-209835301*/count=88; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.tanh((( ~ Math.tanh(-Number.MIN_SAFE_INTEGER)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-209835301*/count=89; tryItOut("\"use strict\"; Array.prototype.sort.apply(g0.a1, [(function() { try { i2.next(); } catch(e0) { } try { /*MXX3*/g0.URIError.prototype.constructor = g1.URIError.prototype.constructor; } catch(e1) { } try { v0 = x; } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(b2, o2); throw f2; }), g0]);");
/*fuzzSeed-209835301*/count=90; tryItOut("/*hhh*/function vzqxjd(){m1.set(m1, this.v0);}vzqxjd();");
/*fuzzSeed-209835301*/count=91; tryItOut("");
/*fuzzSeed-209835301*/count=92; tryItOut("mathy4 = (function(x, y) { return Math.imul(( ~ Math.min(y, Math.max(( + Number.MIN_SAFE_INTEGER), (y ? -Number.MAX_VALUE : Math.fround(( + Math.fround(y))))))), Math.fround(mathy2(Math.fround((( + ((Math.imul((Math.max((( ~ (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0), (( - (x | 0)) | 0)) | 0), (x | 0)) | 0) | 0)) | 0)), Math.fround(Math.fround(Math.atan2(( ~ ( + (( + y) ** x))), Math.fround(Math.round(Math.log(x))))))))); }); testMathyFunction(mathy4, [42, 2**53, 0/0, 0x0ffffffff, -0x080000001, 1/0, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -0x0ffffffff, 1.7976931348623157e308, -(2**53-2), Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 2**53+2, 2**53-2, -(2**53+2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, 0x100000001, -0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, 1, 0, -0x100000001, -0x100000000, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-209835301*/count=93; tryItOut("mathy5 = (function(x, y) { return (( ~ (((((Math.cosh(x) >>> 0) % ((-0x100000001 / Math.tanh(( ~ y))) >>> 0)) >>> 0) / (( ~ (( + (y - (((((x >>> 0) || y) >>> 0) >>> 0) + (y * y)))) >>> 0)) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-209835301*/count=94; tryItOut("a0 = r0.exec(g2.s2);\ns2 + '';\n");
/*fuzzSeed-209835301*/count=95; tryItOut("/*RXUB*/var r = /(?!(?:(?!(?!\\cT)|[^]))\\B\\b+?(?=[^])|\\b\\cM{2,2}{1})|\\u1E5A(${4}\\d|\u9807+?[^]{4,8}([\\w\\s\u0082\\s]{0,3})|.)*?/yim; var s = (/*MARR*/[function(){}, function(){}, Infinity, {x:3}, function(){}, Infinity, function(){}, Infinity, function(){}, Infinity, Infinity, {x:3}, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, {x:3}, {x:3}, function(){}, Infinity].map >>> (String.prototype.padStart)(((y = -11))(x, (makeFinalizeObserver('nursery')))))(new String(new Uint8ClampedArray(-8).valueOf(\"number\").__defineGetter__(\"getter\", decodeURI), arguments[\"getFloat64\"] = ((window) =  /x/ )), (Math.max([1,,], 28))); print(uneval(s.match(r))); ");
/*fuzzSeed-209835301*/count=96; tryItOut("\"use asm\"; m2.delete(g0);");
/*fuzzSeed-209835301*/count=97; tryItOut("var ghoamx = new SharedArrayBuffer(4); var ghoamx_0 = new Float32Array(ghoamx); print(ghoamx_0[0]); ghoamx_0[0] = -29; var ghoamx_1 = new Int16Array(ghoamx); ghoamx_1[0] = 13; var ghoamx_2 = new Int32Array(ghoamx); var ghoamx_3 = new Int8Array(ghoamx); ghoamx_3[0] = -23; var ghoamx_4 = new Int32Array(ghoamx); ghoamx_4[0] = -27; var ghoamx_5 = new Int32Array(ghoamx); print(ghoamx_5[0]); ghoamx_5[0] = 24; var ghoamx_6 = new Int16Array(ghoamx); print(ghoamx_6[0]); var ghoamx_7 = new Uint8ClampedArray(ghoamx); ghoamx_7[0] = -1481660203.5; var ghoamx_8 = new Int16Array(ghoamx); print(ghoamx_8[0]); ghoamx_8[0] = -21; var ghoamx_9 = new Int32Array(ghoamx); h1 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.splice.call(a0, NaN, ({valueOf: function() { ;return 10; }}));; var desc = Object.getOwnPropertyDescriptor(f2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var v of s0) { try { o0.v1 = (v2 instanceof t2); } catch(e0) { } s1 += 'x'; }; var desc = Object.getPropertyDescriptor(f2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { m0.has(e0);; Object.defineProperty(f2, name, desc); }, getOwnPropertyNames: function() { print( /x/g );; return Object.getOwnPropertyNames(f2); }, delete: function(name) { h2 + '';; return delete f2[name]; }, fix: function() { e1.add(g0);; if (Object.isFrozen(f2)) { return Object.getOwnProperties(f2); } }, has: function(name) { /*MXX1*/o0.o0 = g1.Promise.race;; return name in f2; }, hasOwn: function(name) { ; return Object.prototype.hasOwnProperty.call(f2, name); }, get: function(receiver, name) { /*ODP-1*/Object.defineProperty(s1, \"window\", ({enumerable: false}));; return f2[name]; }, set: function(receiver, name, val) { v2 = 4.2;; f2[name] = val; return true; }, iterate: function() { a0.reverse(g1);; return (function() { for (var name in f2) { yield name; } })(); }, enumerate: function() { return o2; var result = []; for (var name in f2) { result.push(name); }; return result; }, keys: function() { g0.g1.offThreadCompileScript(\"function f0(this.o1)  { \\\"use strict\\\"; \\\"use asm\\\"; throw  /x/g ; } \");; return Object.keys(f2); } });a1.forEach((function(j) { if (j) { try { m0.delete(s0); } catch(e0) { } try { e2.has(o1); } catch(e1) { } s1 += s2; } else { try { s1 += 'x'; } catch(e0) { } try { v0 = t1.length; } catch(e1) { } try { e0.add(e0); } catch(e2) { } s0 += 'x'; } }));v1 = (f2 instanceof s1);s2 += 'x';(Math.atan2(-0, ((void shapeOf(\"\\u6D5C\")))));Array.prototype.reverse.apply(this.a1, []);print(ghoamx_5[4]);");
/*fuzzSeed-209835301*/count=98; tryItOut("for(var d in ((Date.prototype.getUTCMinutes)( \"\" )))v1 = this.g0.eval(\"v2 = a2.length;\");");
/*fuzzSeed-209835301*/count=99; tryItOut("var jxcikh = new ArrayBuffer(4); var jxcikh_0 = new Uint8Array(jxcikh); jxcikh_0[0] = 27; var jxcikh_1 = new Int16Array(jxcikh); var jxcikh_2 = new Int32Array(jxcikh); print(jxcikh_2[0]); jxcikh_2[0] = -20; var jxcikh_3 = new Uint8Array(jxcikh); jxcikh_3[0] = 0; var jxcikh_4 = new Float32Array(jxcikh); jxcikh_4[0] = 16; var jxcikh_5 = new Int32Array(jxcikh); jxcikh_5[0] = 3; var jxcikh_6 = new Int16Array(jxcikh); print(jxcikh_6[0]); /* no regression tests found */for (var v of g2) { try { t2[4] = new RegExp(\"((?=^)?)\", \"m\"); } catch(e0) { } m0.set(this, e0); }( \"\" );o2 = Object.create(b1);");
/*fuzzSeed-209835301*/count=100; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i1);\n    }\n    i0 = ((String.prototype.repeat)());\n    i1 = (((({\"22\": x }))) > (35184372088833.0));\n    return (((i0)+((((((0x6fd2fbe) != (-0x8000000)) ? ((0x57d5ec7a) < (0x76869355)) : ((0x37c1fbf3)))-(i0))>>>((0x0) / (0x0))) == (((((0xffffffff)-(-0x8000000)) & ((!(0x59b83999)))) % (((0xa28f1c6c)-(0xee45aba0)) << (-0xe8c41*(0x36a5f9d0))))>>>((((0x1a96f870) ? (0x69237824) : (0xff935f56)) ? (i1) : ((0x0) != (0x77e82144))))))))|0;\n  }\n  return f; })(this, {ff: Object.prototype.toLocaleString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0, -Number.MIN_VALUE, -(2**53-2), -1/0, -0x100000000, 0x07fffffff, Number.MAX_VALUE, 0x080000001, 0x100000001, -0x100000001, Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, Number.MIN_VALUE, 1/0, -0, -0x080000001, 0x080000000, 0/0, 0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, -(2**53+2), 0x0ffffffff, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, 2**53+2, -(2**53)]); ");
/*fuzzSeed-209835301*/count=101; tryItOut("(4277);");
/*fuzzSeed-209835301*/count=102; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - (Math.acos(mathy1(0x07fffffff, Math.fround(mathy2(Math.fround(y), Math.fround(-0x07fffffff))))) >>> 0)); }); testMathyFunction(mathy4, [0x080000000, 2**53, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, 42, -0x100000000, Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, -0x080000000, 1, 0x100000001, 2**53+2, -(2**53), Math.PI, 0x080000001, 0x07fffffff, -0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, -0x07fffffff, -1/0, -(2**53+2), 0, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=103; tryItOut("\"use strict\"; w.stack;let(c) ((function(){(x);})());");
/*fuzzSeed-209835301*/count=104; tryItOut("\"use strict\"; /*bLoop*/for (let knovca = 0, (x <<= x); knovca < 143; ++knovca) { if (knovca % 2 == 1) { for (var v of g1.v2) { v0.toString = (function() { for (var j=0;j<13;++j) { o0.f1(j%2==1); } }); } } else { /*bLoop*/for (let mclglg = 0; mclglg < 6; ++mclglg) { if (mclglg % 3 == 2) { Array.prototype.pop.call(o1.a0); } else { L:if(false) { if (/\\b/im) print(new RegExp(\"(?!(?!(?=(?!(?:(?:[^]))))))(?!(?:[^]))\", \"gm\"));} else t2.set(t2, 13); }  }  }  } ");
/*fuzzSeed-209835301*/count=105; tryItOut(";");
/*fuzzSeed-209835301*/count=106; tryItOut("\"use strict\"; y.stack;g2.e1.add(a0);");
/*fuzzSeed-209835301*/count=107; tryItOut("/*MARR*/[NaN, function(){}, [1], [1], NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN]");
/*fuzzSeed-209835301*/count=108; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( - ((( + Math.min(( + (((( + -0x0ffffffff) >>> 0) >> (Math.PI >>> 0)) ? (((Number.MAX_VALUE >>> 0) || (y >>> 0)) >>> 0) : 0x100000001)), y)) % ( - ((x || Math.fround(( ~ y))) | 0))) >>> 0)); }); testMathyFunction(mathy0, [2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 1, 0x100000001, -(2**53-2), -0x100000001, 2**53, 0x100000000, 1/0, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), Number.MIN_VALUE, 0x0ffffffff, 0/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -0x0ffffffff, -0x080000000, -0x07fffffff, 0, 42, Number.MAX_VALUE, -0x080000001, -1/0, -0, Math.PI]); ");
/*fuzzSeed-209835301*/count=109; tryItOut("do {o2.e1 = new Set; } while((this == \u0009/*UUV1*/(a.add = function(y) { \"use strict\"; yield y; print([] = new RegExp(\"$\", \"m\") <= new RegExp(\"(?!(?!\\\\B))\", \"gm\"));; yield y; })) && 0);");
/*fuzzSeed-209835301*/count=110; tryItOut("t2 = p0;");
/*fuzzSeed-209835301*/count=111; tryItOut("t2[18];/*vLoop*/for (var fjzfwy = 0; fjzfwy < 2; ++fjzfwy) { var b = fjzfwy; a0.sort(f2); } ");
/*fuzzSeed-209835301*/count=112; tryItOut("\"use strict\"; throw (((z | 0) ? (Number.MIN_VALUE | 0) : (z >>> 0)) | 0);const z = Object.defineProperty(w, \"length\", ({enumerable: false}));");
/*fuzzSeed-209835301*/count=113; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + mathy0(( + (Math.cosh(y) + (Math.expm1((Math.log10((Math.atan2(Number.MAX_SAFE_INTEGER, -(2**53-2)) | Math.fround(( ~ y)))) | 0)) | 0))), ( + Math.max(((( + y) >> ( + x)) & Math.fround(( - y))), Math.abs(( + (y ? ( + Math.min(( + -1/0), ( + x))) : Math.fround(Math.asinh(x))))))))); }); ");
/*fuzzSeed-209835301*/count=114; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    {\n      switch ((imul((i0), (!(i0)))|0)) {\n        case -3:\n          i1 = (i0);\n          break;\n        case -2:\n          i1 = (!(!(i0)));\n          break;\n        case -3:\n          i0 = (0x437cdab2);\n          break;\n        default:\n          i1 = ((((makeFinalizeObserver('tenured'))) | ((i0)-(i1)+(/*FFI*/ff(((+((Float32ArrayView[((0x80d07ef8) % (0x0)) >> 2])))), ((129.0)))|0))));\n      }\n    }\n    i1 = (i0);\n    return +((+abs(((8388608.0)))));\n  }\n  return f; })(this, {ff: Number}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [(function(){return 0;}), null, 0, (new String('')), objectEmulatingUndefined(), undefined, /0/, '\\0', [0], (new Boolean(false)), -0, 0.1, ({valueOf:function(){return 0;}}), (new Boolean(true)), '', true, [], NaN, false, ({valueOf:function(){return '0';}}), '/0/', (new Number(0)), (new Number(-0)), 1, ({toString:function(){return '0';}}), '0']); ");
/*fuzzSeed-209835301*/count=115; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((( + (Math.min(( - ( + x)), ( + Math.sqrt((-Number.MAX_VALUE >>> 0)))) | 0)) | 0) >= (Math.pow(((Math.cbrt(( - (0 | 0))) >>> 0) >>> 0), (( + Math.fround((Math.cos((y >>> 0)) >>> 0))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, [0x080000000, -0x100000000, 0, Math.PI, -0x0ffffffff, 0x0ffffffff, 2**53+2, 0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 2**53-2, -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x100000001, -(2**53), -(2**53+2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -0x080000001, 0x080000001, 1/0, 0x100000001, -1/0, 2**53, -0, Number.MIN_SAFE_INTEGER, 0/0, 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=116; tryItOut("testMathyFunction(mathy4, [0.000000000000001, 2**53+2, -0x080000000, -0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, 42, 0x0ffffffff, -1/0, -(2**53), Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 1, -(2**53+2), 2**53-2, -(2**53-2), 0/0, 0x080000001, -0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -0, -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=117; tryItOut("let c =  /x/g .eval(\" /x/ \");e0 + '';");
/*fuzzSeed-209835301*/count=118; tryItOut("\"use strict\"; v2 = a1.length;");
/*fuzzSeed-209835301*/count=119; tryItOut("/*RXUB*/var r = new RegExp(\"((?:.|\\\\d.|[^]|\\\\u000E)*|[^])|[^-\\\\S\\u001e-\\\\\\ue5e7\\\\0-\\\\\\ud308]|^*$|(?:.+(?:(?=^)))|^\", \"i\"); var s = \"\\u00aeK \"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=120; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\u0083|(?:(?=^\\f)){0,3}\\xcE(?!\\u0091)|\\3+?|(?:\\1{4})){0}/yi; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=121; tryItOut("for (var p in i0) { a1.sort((function() { try { a0.toSource = (function() { try { g1.g1.v2 = (o0.o1.s0 instanceof i0); } catch(e0) { } /*RXUB*/var r = r1; var s = \"\\n\\n\\n\\n\"; print(s.replace(r, yield r, \"gy\")); print(r.lastIndex);  return o1; }); } catch(e0) { } o0.v2 = (x % 47 == 26); return b0; })); }");
/*fuzzSeed-209835301*/count=122; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return (Math.fround(((Math.max(( + (Math.min((y | 0), y) | 0)), ( + ( ~ (Math.max(y, y) | 0)))) >>> 0) ? (( ~ y) >>> 0) : (( + Math.asin(( ! -Number.MAX_VALUE))) >>> 0))) == ( - ( - y))); }); ");
/*fuzzSeed-209835301*/count=123; tryItOut("print(uneval(e0));Array.prototype.shift.call(a0, v2, m1, s2, t1, g0.h2);");
/*fuzzSeed-209835301*/count=124; tryItOut("\"use strict\"; var rncokj, x = x, x, b = (4277), coqsbj, x = Math.hypot(this, -26), zjxquc, fvmkiw, dvndkm, tnbxfw\u000c;/*RXUB*/var r = new RegExp(\"((?:(\\\\3)|(\\\\2)?*))\", \"m\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=125; tryItOut("/*infloop*/for(c = (makeFinalizeObserver('tenured')); x; x) o1.f2(e0);");
/*fuzzSeed-209835301*/count=126; tryItOut("for (var v of g0) { t1.valueOf = (function() { v1 = evaluate(\"(new Symbol( /x/g ))\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 62 == 10), sourceIsLazy: (x % 2 == 1), catchTermination: true, element: o0, elementAttributeName: s0, sourceMapURL: s0 })); return t0; }); }");
/*fuzzSeed-209835301*/count=127; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, [/0/, '\\0', 1, (new Number(0)), 0, (new Number(-0)), [], '0', objectEmulatingUndefined(), [0], ({valueOf:function(){return 0;}}), NaN, undefined, ({valueOf:function(){return '0';}}), true, (new Boolean(true)), (function(){return 0;}), 0.1, (new Boolean(false)), false, null, '', ({toString:function(){return '0';}}), -0, (new String('')), '/0/']); ");
/*fuzzSeed-209835301*/count=128; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(( + Math.fround(mathy1(Math.fround(Math.cbrt(Math.fround(Math.atan2(mathy1(Math.atan(y), -0x07fffffff), x)))), (( + (Math.fround((Math.fround((y !== ( + (((-(2**53-2) | 0) , (-0x07fffffff | 0)) | 0)))) % Math.fround(x))) != (y != y))) * ( + ( ~ (Math.max(x, ( + x)) | 0)))))))); }); testMathyFunction(mathy2, [-0x0ffffffff, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, 0x07fffffff, -(2**53), 0.000000000000001, -(2**53-2), -0x100000001, -0x080000000, 1, Number.MIN_SAFE_INTEGER, 0, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0, 0x100000000, 2**53, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -1/0, Math.PI, -(2**53+2), 0x100000001, Number.MAX_VALUE, 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, 42, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=129; tryItOut("e0.add(((function fibonacci(hktmlo) { ; if (hktmlo <= 1) { ; return 1; } ; return fibonacci(hktmlo - 1) + fibonacci(hktmlo - 2);  })(2)));");
/*fuzzSeed-209835301*/count=130; tryItOut("\"use strict\"; yield;\n{}\n");
/*fuzzSeed-209835301*/count=131; tryItOut("\"use strict\"; g0.e2.add(p1);");
/*fuzzSeed-209835301*/count=132; tryItOut("while(((x - eval)) && 0)continue ;");
/*fuzzSeed-209835301*/count=133; tryItOut("Array.prototype.sort.apply(a2, [(function(j) { if (j) { print(uneval(v2)); } else { try { a2.pop(m1); } catch(e0) { } try { /*MXX1*/o2 = g0.g0.Object.getOwnPropertyNames; } catch(e1) { } s1 += s1; } }), o1, this.i2]);");
/*fuzzSeed-209835301*/count=134; tryItOut("a0.shift(o2.b2, v1, o1);");
/*fuzzSeed-209835301*/count=135; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.log2((Math.min(Math.fround(Math.atanh(Math.fround(( + (( + 42) ? ( + y) : (y >>> 0)))))), ( + ( + x))) | 0)) | (( + Math.atan2(( + Math.hypot((-Number.MIN_VALUE >>> 0), (Math.atanh(Math.imul(Math.pow(y, (x | 0)), ( + Math.pow((y >>> 0), ( + x))))) >>> 0))), ((Math.atanh(((x > (Math.max((0 | 0), x) | 0)) | 0)) >>> 0) >>> (Math.fround(( + ( + 0x100000001))) && Math.fround((Math.fround(Math.max(0, ( ~ (y >>> 0)))) && Math.fround((y != y)))))))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x0ffffffff, -0x080000000, 0x080000000, 1, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -1/0, 0, 42, -Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 1/0, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, -(2**53), Math.PI, 0x080000001, 0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, -0x100000001, -(2**53+2), 0/0, 0x100000000]); ");
/*fuzzSeed-209835301*/count=136; tryItOut("/*ADP-1*/Object.defineProperty(a0, 19, ({value:  \"\"  ^ /(?:(?:\\B))/gyi, writable: (/*UUV1*/(x.isView = q => q)), configurable: (x % 80 == 33), enumerable: (x % 4 != 0)}));");
/*fuzzSeed-209835301*/count=137; tryItOut("g1.offThreadCompileScript(\"new SyntaxError((x)((makeFinalizeObserver('nursery'))))\");");
/*fuzzSeed-209835301*/count=138; tryItOut("\"use strict\"; v1 = evalcx(\"function f2(m1) \\\"use asm\\\";   var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    var d3 = -3.094850098213451e+26;\\n    var i4 = 0;\\n    return +((Float64ArrayView[((i2)) >> 3]));\\n  }\\n  return f;\", g0);");
/*fuzzSeed-209835301*/count=139; tryItOut("v2 = (b2 instanceof g1.a1);");
/*fuzzSeed-209835301*/count=140; tryItOut("v1 = (b2 instanceof p1);");
/*fuzzSeed-209835301*/count=141; tryItOut("\"use strict\"; x;");
/*fuzzSeed-209835301*/count=142; tryItOut("mathy0 = (function(x, y) { return (((( + (( + 0x0ffffffff) | ( + Math.tan((( + Math.max(( + 1/0), ( + Math.fround(Math.max(Math.fround(x), (Math.PI >>> 0)))))) >>> 0))))) << ((( + x) | 0) ? Math.fround(( ~ Math.fround(Math.log(y)))) : (Math.pow(((((( ~ 2**53) | 0) == y) | 0) >>> 0), ((Math.asinh(x) | 0) >>> 0)) <= Math.atan2(( + Math.min(0x0ffffffff, ( + -Number.MIN_SAFE_INTEGER))), Math.fround(( - Math.fround(y))))))) >>> 0) <= (Math.atan((Math.imul((x | 0), x) | 0)) | 0)); }); testMathyFunction(mathy0, /*MARR*/[(1/0), ( '' .__defineSetter__(\"b\", (let (e=eval) e))), (1/0), ( '' .__defineSetter__(\"b\", (let (e=eval) e))), ['z'], ['z'],  /x/g , ( '' .__defineSetter__(\"b\", (let (e=eval) e))), ( '' .__defineSetter__(\"b\", (let (e=eval) e)))]); ");
/*fuzzSeed-209835301*/count=143; tryItOut("\"use strict\"; b;g0.g2.o1.a2.pop(e2, m0, f1);");
/*fuzzSeed-209835301*/count=144; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=145; tryItOut("e2.has(f2);");
/*fuzzSeed-209835301*/count=146; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( + (Math.pow(x, Math.sign((Math.cos((x >>> 0)) | 0))) < ( + Math.expm1(2**53))))) ^ (((mathy2((y ^ y), ( + Math.ceil(( + y)))) | 0) % (( + (mathy4(y, ((2**53+2 != y) >>> 0)) ? Math.log((0x100000001 >>> 0)) : Math.sign(-Number.MIN_VALUE))) | 0)) | 0))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, 0x0ffffffff, 1, 42, 1.7976931348623157e308, -0x080000000, -0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 0x100000000, 0x100000001, 0x07fffffff, 0, -0x100000000, 2**53+2, 1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, -(2**53), -(2**53+2), Math.PI, 0x080000001, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=147; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( + ( ~ (Math.min(Math.imul((mathy1(x, y) >>> x), mathy3(y, ( + -0x080000000))), x) >>> 0))) ? Math.hypot(( + (( + ( + (( + Math.min(Math.fround((y & x)), ( + mathy2((x >>> 0), ( + (-Number.MIN_VALUE ? ( + y) : ( + x))))))) > ( + ( ~ -0x07fffffff))))) > ( + (Math.clz32((y | 0)) | 0)))), (Math.exp((y >>> 0)) >>> 0)) : (Math.max((Math.fround((( ~ (( ~ ((Math.fround(y) !== Math.fround(x)) >>> 0)) | 0)) >>> 0)) * Math.fround((( + (x || -Number.MIN_SAFE_INTEGER)) ? 0x07fffffff : Math.atanh((x | 0))))), Math.fround((Math.fround(Math.cosh(Math.fround(x))) != Math.fround(Math.atan2(Math.cbrt(((y < x) | 0)), Math.hypot((( ! y) | 0), -(2**53))))))) | 0)) | 0); }); testMathyFunction(mathy4, [-0, -0x0ffffffff, 1, 2**53-2, 0/0, Number.MIN_VALUE, 0x100000000, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, -(2**53-2), 0x07fffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000001, -0x080000001, -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, -(2**53), Math.PI, 2**53, 42, 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), -0x100000000, 0, Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-209835301*/count=148; tryItOut("\"use strict\"; g2.g1.m1 = new Map(i1);");
/*fuzzSeed-209835301*/count=149; tryItOut("\"use strict\"; var tyxxoe, nphjbs, x = (ArrayBuffer((-24 === 14), \"\\u7253\")) ** x, z =  '' , ulswnc, otjxce, x = (-26 ,  \"\" ), zpqtcb;t1 = this.t1.subarray(17);");
/*fuzzSeed-209835301*/count=150; tryItOut("\"use strict\"; /*RXUB*/var r = ((function sum_slicing(emrxiy) { ; return emrxiy.length == 0 ? 0 : emrxiy[0] + sum_slicing(emrxiy.slice(1)); })(/*MARR*/[new Boolean(false),  /x/ ,  /x/ ,  /x/ ,  /x/ , (1/0),  /x/ , new Boolean(false), new Boolean(false), (1/0), (1/0), new Boolean(false), (1/0), new Boolean(false), (1/0), (1/0), (1/0), new Boolean(false), (1/0), (1/0),  /x/ ,  /x/ ,  /x/ , (1/0),  /x/ , (1/0), (1/0), (1/0), (1/0),  /x/ ,  /x/ , (1/0),  /x/ , (1/0), new Boolean(false), (1/0), new Boolean(false),  /x/ , (1/0),  /x/ , (1/0), new Boolean(false), (1/0), new Boolean(false),  /x/ ,  /x/ , new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false),  /x/ ])); var s = \"\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\\na\\u6f06\\u6f06\"; print(s.replace(r, \"\\u788D\")); ");
/*fuzzSeed-209835301*/count=151; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[ \"\" ,  \"\" , new Number(1.5),  /x/ , new Number(1.5),  \"\" ,  /x/ , 2**53-2,  \"\" ,  \"\" , new Number(1.5), new Number(1.5),  \"\" ,  \"\" ,  \"\" , 2**53-2,  /x/ , 2**53-2, new Number(1.5),  /x/ , new Number(1.5), 2**53-2, new Number(1.5), 2**53-2,  /x/ , new Number(1.5), new Number(1.5), 2**53-2, 2**53-2, new Number(1.5),  \"\" , new Number(1.5), 2**53-2,  /x/ , 2**53-2, new Number(1.5),  \"\" , new Number(1.5),  /x/ ]) { v1 = true; }");
/*fuzzSeed-209835301*/count=152; tryItOut("let w = timeout(1800);var gwvoia = new ArrayBuffer(2); var gwvoia_0 = new Uint8ClampedArray(gwvoia); /*hhh*/function jyapah(d){let v2 = t1.byteOffset;}/*iii*/print(x);break L;var x = (makeFinalizeObserver('nursery'));v0 = new Number(e0);");
/*fuzzSeed-209835301*/count=153; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return Math.fround(( + Math.fround(Math.sinh((mathy1((( ! (Math.max(-Number.MAX_SAFE_INTEGER, Math.fround((mathy1(2**53-2, (y | 0)) | 0))) | 0)) | 0), Math.pow(y, x)) - Math.hypot(( - (( + 0) >>> x)), (((y | 0) - x) | 0))))))); }); testMathyFunction(mathy2, [-1/0, 0x080000001, -(2**53), 0x100000000, 0/0, 0x07fffffff, -0x080000000, -(2**53+2), -0x0ffffffff, -0x080000001, 0.000000000000001, -0, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 2**53-2, 1, 0x100000001, 2**53, 42, -0x07fffffff, Number.MAX_VALUE, 0, 0x0ffffffff, 1/0, -0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=154; tryItOut("\"use strict\"; a2.shift();\nreturn \"\\u242E\";\n");
/*fuzzSeed-209835301*/count=155; tryItOut("");
/*fuzzSeed-209835301*/count=156; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( + (mathy0(((y ? (Math.cbrt((42 >>> 0)) >= x) : x) << (mathy2(y, Math.atan2(x, ( + ((0x07fffffff ? (y >>> 0) : (y >>> 0)) | 0)))) + (mathy1(((0x07fffffff >>> (-Number.MAX_VALUE >>> 0)) | 0), ((((-Number.MIN_VALUE >>> 0) % x) >>> 0) | 0)) | 0))), (Math.pow(Math.fround(Math.fround((Math.fround(y) + Math.fround(y)))), (( ! (0 | 0)) | 0)) >> Math.abs((Math.fround((42 || Math.fround(x))) > (( + (( + y) << x)) | 0))))) | 0))); }); testMathyFunction(mathy3, [-0x100000001, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, 1/0, 0, 0x080000001, -Number.MAX_VALUE, 0x100000001, 2**53+2, -(2**53-2), -0x100000000, 0x100000000, 0x07fffffff, 42, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 2**53, -0x07fffffff, -0x080000001, -(2**53), -0x080000000, -0, 1.7976931348623157e308, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-209835301*/count=157; tryItOut("mathy4 = (function(x, y) { return Math.log2(Math.fround(mathy0((mathy3((Math.fround(Math.min(Math.fround((Math.min(x, x) >>> 0)), Math.fround(( + Math.min(( + Math.atan2(y, y)), ( + Number.MAX_VALUE)))))) | 0), -0x100000000) | 0), Math.acosh(Math.acos(((y ^ ( + mathy0((( - (y >>> 0)) >>> 0), y))) | 0)))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -(2**53+2), Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, 1, -(2**53), -0x080000000, -0x07fffffff, 2**53-2, -0x0ffffffff, 42, -0, 0x080000001, 0/0, 0, 1/0, 2**53, -0x100000001, 0x080000000, -1/0]); ");
/*fuzzSeed-209835301*/count=158; tryItOut("m2.set(this.f2, e1);");
/*fuzzSeed-209835301*/count=159; tryItOut("\"use strict\"; with(x++){(c = window, ...\u3056) => [[]] }");
/*fuzzSeed-209835301*/count=160; tryItOut("testMathyFunction(mathy1, [-0x07fffffff, 0x100000001, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, 42, -0x100000001, 2**53-2, 2**53, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, -Number.MAX_VALUE, -0, 0x080000000, 0x100000000, -1/0, -0x100000000, 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, 1, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 0/0, 0, -(2**53-2), -Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-209835301*/count=161; tryItOut("a1.length = 15;");
/*fuzzSeed-209835301*/count=162; tryItOut("mathy4 = (function(x, y) { return Math.acosh(( + Math.hypot((( + Math.pow(x, (( + Math.log(( + (Math.fround(y) <= (Math.pow((((y | 0) != (y | 0)) | 0), x) >>> 0))))) | 0))) >>> 0), mathy1((Math.atan(x) >>> 0), Math.sinh(-Number.MIN_VALUE))))); }); testMathyFunction(mathy4, [-1/0, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), 0x100000001, 2**53, -0, 2**53-2, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 1/0, 0x0ffffffff, Math.PI, -0x100000001, 0x080000001, 0x100000000, 0/0, -(2**53-2), 42, 0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-209835301*/count=163; tryItOut("/*hhh*/function rribht(){(((makeFinalizeObserver('tenured'))));}rribht();");
/*fuzzSeed-209835301*/count=164; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=165; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=166; tryItOut("t1[1] = b2;");
/*fuzzSeed-209835301*/count=167; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.min(Math.hypot(Math.acosh((( + (Math.fround(y) ? (0x07fffffff >>> 0) : x)) | 0)), (Math.fround(( + (((Math.expm1(y) | 0) | 0) | (y !== (y | 0))))) + -Number.MAX_VALUE)), (Math.ceil((Math.ceil((Math.hypot((x * Math.pow(( + y), x)), (( + ( ~ ((x >> ( - x)) >>> 0))) >>> 0)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 0.000000000000001, -0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, -1/0, 0x100000000, 0/0, 2**53-2, Math.PI, -0x080000001, -(2**53+2), -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, 1.7976931348623157e308, -0x080000000, 2**53, 42, 0x080000000, -0, 2**53+2, 0x07fffffff, -(2**53), 1, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=168; tryItOut("g2.v0 = (g0 instanceof p0);");
/*fuzzSeed-209835301*/count=169; tryItOut("/*infloop*/ for (let x\u000d of x) {M:if(new function(y) { \"use strict\"; return true }(\"\\u3652\")) { if (allocationMarker()) print( \"\" );} else {a2.sort((function(j) { if (j) { try { s2 += s1; } catch(e0) { } m2 = new WeakMap; } else { try { for (var p in i2) { try { a1 = new Array; } catch(e0) { } for (var v of e0) { try { o0.a2.pop(); } catch(e0) { } e1.has(b0); } } } catch(e0) { } try { Array.prototype.splice.apply(a1, [3, 5, m1]); } catch(e1) { } try { m2.delete(this.a1); } catch(e2) { } print(m0); } })); /x/ ; } }");
/*fuzzSeed-209835301*/count=170; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.max(( + ( + ((Math.log10((( + ( + ( + y))) >>> 0)) >>> 0) >>> 0))), Math.fround(Math.asin(Math.fround(Math.hypot(Math.abs(Math.fround((y || (y >>> 0)))), Math.max(y, Math.asin(0x100000000)))))))); }); testMathyFunction(mathy0, [0.000000000000001, 0, -Number.MAX_VALUE, -0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, 2**53-2, 0x07fffffff, -0x07fffffff, -0, Number.MAX_VALUE, -1/0, 42, 2**53, 0x100000001, 1, 0x0ffffffff, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, -0x080000001, 1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 2**53+2]); ");
/*fuzzSeed-209835301*/count=171; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-209835301*/count=172; tryItOut("v2 = false;\n(14);\n");
/*fuzzSeed-209835301*/count=173; tryItOut("mathy1 = (function(x, y) { return ( + Math.acosh((Math.log2((0x080000000 | 0)) | 0))); }); testMathyFunction(mathy1, /*MARR*/[true, {}]); ");
/*fuzzSeed-209835301*/count=174; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=175; tryItOut("mathy0 = (function(x, y) { return (((Math.atan2((( - Math.fround(Math.exp((Math.fround(Math.trunc(x)) | 0)))) | 0), (((Math.fround(Math.log1p(y)) >>> 0) !== (Math.imul(((x <= Math.fround(y)) >>> 0), Math.fround(( + Math.atan2((x , -0x0ffffffff), ( + ( ~ Number.MIN_SAFE_INTEGER)))))) | 0)) >>> 0)) | 0) ? (Math.atan2(((( + ( ! x)) > ( + (( + y) >>> 0))) | 0), ( + (( + ( + x)) * ( + Math.cosh(y))))) | 0) : (Math.atanh(Math.pow(((((y | 0) != -(2**53-2)) | 0) >>> 0), ( + (( + x) >= ( + y))))) | 0)) | 0); }); testMathyFunction(mathy0, [-0, (new Boolean(true)), (new String('')), objectEmulatingUndefined(), true, '0', '/0/', undefined, '\\0', (new Number(-0)), ({valueOf:function(){return '0';}}), [0], 1, 0.1, [], (function(){return 0;}), null, (new Boolean(false)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), NaN, false, /0/, 0, (new Number(0)), '']); ");
/*fuzzSeed-209835301*/count=176; tryItOut("/*oLoop*/for (let gdybuv = 0; gdybuv < 72; ++gdybuv) { print(x);\nb1 = t0.buffer;\n } ");
/*fuzzSeed-209835301*/count=177; tryItOut("i2.__iterator__ = (function() { try { a1 = Array.prototype.filter.call(a0, String.prototype.trimRight.bind(g2.v2), v0, g0.h1, x, g1, o1, g1, p2, v1); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a0, 4, ({})); } catch(e1) { } try { ; } catch(e2) { } o0.g2.v2 = evalcx(\"/*FARR*/[].filter(() => /*RXUE*/new RegExp(\\\"(?![^\\\\\\\\S\\\\\\\\w\\\\u38e1\\\\\\\\W])*?|.*?*|\\\\\\\\1{2,}\\\\\\\\d.\\\", \\\"gm\\\").exec(\\\"\\\").eval(\\\"((yield \\\\\\\"\\\\\\\\uD93D\\\\\\\"))\\\"))\", g0); return h1; });");
/*fuzzSeed-209835301*/count=178; tryItOut("/*RXUB*/var r = /(?!(?=(?=(?:\\D))?)|(?:(?:$)*).\\s|\\0{1,3}[^]*{3,3}(?:(?:\\S))?)/gm; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-209835301*/count=179; tryItOut("\"use strict\"; a0.reverse();");
/*fuzzSeed-209835301*/count=180; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=181; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\W\", \"i\"); var s = b = ({e: (Math.asin({})) }); print(r.test(s)); ");
/*fuzzSeed-209835301*/count=182; tryItOut("\"use strict\"; o2.a0.shift();");
/*fuzzSeed-209835301*/count=183; tryItOut("s0 += 'x';\n/* no regression tests found */\n");
/*fuzzSeed-209835301*/count=184; tryItOut("mathy0 = (function(x, y) { return ( + ( + (( + ( ! ( ~ y))) >>> ( + ( ~ ( + (( + x) - ( + (Math.fround(y) % x))))))))); }); testMathyFunction(mathy0, [-0x07fffffff, 1/0, 42, 0x100000001, 2**53-2, 2**53+2, 0x0ffffffff, 2**53, -1/0, -Number.MIN_VALUE, 0, -0x080000001, -(2**53), 1, -0x080000000, -0, Number.MAX_VALUE, 0x100000000, Math.PI, -0x100000000, 0.000000000000001, -0x0ffffffff, 0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-209835301*/count=185; tryItOut("testMathyFunction(mathy1, [-0x100000001, Number.MIN_VALUE, -1/0, 0x0ffffffff, 1, Math.PI, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), -Number.MIN_VALUE, 42, -0x07fffffff, 0x080000000, -(2**53), 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, -0, 0x100000001, 0x07fffffff, 0x080000001, 0, -0x0ffffffff, -(2**53+2), 2**53, 0x100000000, -0x080000000]); ");
/*fuzzSeed-209835301*/count=186; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( + ( ! ( + Math.min(((Math.max(( - x), 0x100000000) == Math.max((Math.imul(( + 1/0), -(2**53)) >>> 0), (Number.MAX_SAFE_INTEGER >>> 0))) >>> 0), ( + ((x >>> y) << (x >> ((x >>> 0) || y)))))))) ? ( ! Math.fround(Math.pow((mathy0(Math.fround(( + Math.asin(Math.fround(y)))), Math.fround(x)) || -0), (Math.fround((Math.fround(x) >= Math.fround(-0x100000001))) | 0)))) : ((((Math.acosh((( + Math.cosh(( + y))) >>> 0)) >>> 0) >>> 0) && (Math.atan2((mathy0((((x ** ( + x)) >>> 0) >>> 0), (Math.fround(( ! Math.fround(x))) >>> 0)) | 0), x) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -0x100000001, -0x0ffffffff, -0x080000000, 0x0ffffffff, 0x100000001, 0, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, 0/0, Number.MAX_VALUE, -(2**53+2), 1, 1.7976931348623157e308, -0, 1/0, -(2**53), 2**53, 0x100000000, 42, 0.000000000000001, -0x07fffffff, 2**53+2, 0x080000000]); ");
/*fuzzSeed-209835301*/count=187; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround(Math.log1p(Math.fround((((( + mathy0(Math.fround((( ~ y) >>> 0)), Math.fround(Math.atan2(y, (0.000000000000001 >>> 0))))) >> x) >> Math.tanh((( + -(2**53-2)) ? (-(2**53+2) | 0) : -0x100000000))) | 0)))), ( ~ ( + Math.hypot(( + Math.sqrt(((Math.fround(mathy0(x, Math.fround(Math.sinh(x)))) ? (x >>> 0) : (x | 0)) >>> 0))), (( + ( ! ( + Math.sinh((Math.max(x, Math.fround(x)) / y))))) | 0))))); }); testMathyFunction(mathy1, [(new Number(0)), false, undefined, 0, /0/, [], '/0/', ({valueOf:function(){return 0;}}), (new Boolean(true)), ({valueOf:function(){return '0';}}), '\\0', [0], null, -0, 0.1, (new String('')), '', ({toString:function(){return '0';}}), (function(){return 0;}), (new Boolean(false)), NaN, 1, (new Number(-0)), true, '0', objectEmulatingUndefined()]); ");
/*fuzzSeed-209835301*/count=188; tryItOut("a0.splice(NaN, 10, o1.o0);");
/*fuzzSeed-209835301*/count=189; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+abs(((Float64ArrayView[4096]))));\n    d0 = (+((d0)));\n    {\n      d1 = ((4277));\n    }\n    (Int8ArrayView[(((((Int32ArrayView[0])) >> ((0x1405a35) / (0x7c208be2))) >= (~~(d1)))+(0x12154e75)) >> 0]) = ((0x9c53ccd8));\n    {\n      (Float64ArrayView[((0xdfaaa553)) >> 3]) = ((d0));\n    }\n    return ((-0xfffff*(0x4114a547)))|0;\n  }\n  return f; })(this, {ff: function (\u3056, x)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=190; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((mathy2((( - (Math.hypot(Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) <= Math.fround(x))), (Math.fround(1.7976931348623157e308) ^ mathy1(-0x080000001, x))) | 0)) | 0), ( - ((Math.tan(0.000000000000001) | 0) - (Math.tan(Math.fround(Number.MAX_VALUE)) | 0)))) >>> 0) - (( ~ Math.imul((Math.atan((y >>> 0)) | 0), Math.fround(x))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0, -0x100000000, 1.7976931348623157e308, -1/0, 0x07fffffff, -(2**53), 2**53, 1, -0x07fffffff, -0x080000001, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, -(2**53-2), 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 0x100000001, -0x080000000, 2**53+2, 0x080000000, 0x080000001, 0x100000000, Number.MAX_VALUE, 0.000000000000001, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, 0]); ");
/*fuzzSeed-209835301*/count=191; tryItOut("var mhovsz = new ArrayBuffer(0); var mhovsz_0 = new Int16Array(mhovsz); print(mhovsz_0[0]); mhovsz_0[0] = -4; var mhovsz_1 = new Uint8Array(mhovsz); mhovsz_1[0] = 29; var mhovsz_2 = new Float32Array(mhovsz); print(mhovsz_2[0]); var mhovsz_3 = new Uint16Array(mhovsz); var mhovsz_4 = new Uint32Array(mhovsz); print(mhovsz_4[0]); var mhovsz_5 = new Uint8Array(mhovsz); mhovsz_5[0] = -0.812; var mhovsz_6 = new Uint8Array(mhovsz); mhovsz_6[0] = -7; var mhovsz_7 = new Uint8ClampedArray(mhovsz); print(mhovsz_7[0]); var mhovsz_8 = new Uint32Array(mhovsz); print(mhovsz_8[0]); mhovsz_8[0] = -22; var mhovsz_9 = new Int16Array(mhovsz); print(mhovsz_9[0]); mhovsz_9[0] = -26; var mhovsz_10 = new Int8Array(mhovsz); m1.set(b0, s2);\nthis.e2 = new Set;\n/*tLoop*/for (let x of /*MARR*/[[(void 0)], [(void 0)], new Boolean(false), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, new Boolean(false), mhovsz_0[4], mhovsz_0[4], [(void 0)], [(void 0)], mhovsz_0[4], new Boolean(false), new Boolean(false), {}, mhovsz_0[4], new Boolean(false), [(void 0)], new Boolean(false), [(void 0)], mhovsz_0[4], [(void 0)], {}, mhovsz_0[4], new Boolean(false), new Boolean(false), mhovsz_0[4]]) { print(mhovsz_8); }/* no regression tests found */m0.has(g1.h2);");
/*fuzzSeed-209835301*/count=192; tryItOut("while((x) && 0){e0.add(this.g2.f0);\ni2 + t2;\n }");
/*fuzzSeed-209835301*/count=193; tryItOut("\"use strict\"; Array.prototype.pop.call(a0);const c = 23;");
/*fuzzSeed-209835301*/count=194; tryItOut("/*bLoop*/for (ysajnx = 0; ysajnx < 23; ++ysajnx) { if (ysajnx % 45 == 2) { while((([((void shapeOf(Math.min(/([^u\\v-\u831d\\d\\W]){3,}/g, 2))) !== (x = 18) ? \n ''  : (void options('strict')))])) && 0)delete o0.a2[new String(\"15\")]; } else { ( \"\" ); }  } ");
/*fuzzSeed-209835301*/count=195; tryItOut("let(c) ((function(){let(c = (({x} = c)), \u3056) ((function(){let(d) { for(let e of /*MARR*/[{x:3}, [1], d, [1], function(){}, function(){}, {x:3}, [1], d, [1], function(){}, d, function(){}, d, d, [1], d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, function(){}, function(){}, function(){}, {x:3}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, d, d, {x:3}, {x:3}, [1], function(){}, [1], [1], function(){}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, d, d, function(){}, d, {x:3}, function(){}, function(){}, function(){}, {x:3}, function(){}, {x:3}, d, function(){}, d, function(){}, [1], d, {x:3}, {x:3}, [1], function(){}, d, [1], function(){}, d, function(){}, d, function(){}, [1], {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, [1], function(){}, d, [1], [1], function(){}, [1], d, [1], [1], function(){}, d, [1], {x:3}, d, function(){}, {x:3}, function(){}, {x:3}, {x:3}, d, d, d, {x:3}, function(){}, d, [1], function(){}, function(){}, function(){}, [1], d, d, {x:3}, d, {x:3}, {x:3}, [1], function(){}, [1], d, function(){}, [1], [1], d, d, [1], d, {x:3}, function(){}, d, [1], {x:3}, d, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], function(){}, d, d, {x:3}, function(){}, [1], [1], {x:3}, function(){}, d, [1]]) return;}})());})());");
/*fuzzSeed-209835301*/count=196; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ~ (Math.trunc(-(2**53)) ? ( ! (y | 0)) : (mathy1((Math.hypot(y, Math.imul(( + mathy0(x, y)), Math.sqrt(y))) >>> 0), ((Math.fround((Math.fround(Math.imul(Number.MIN_SAFE_INTEGER, y)) - Math.fround(( + Math.fround(x))))) ? Math.imul(Math.atanh(y), Math.fround(((y >= -Number.MAX_SAFE_INTEGER) | 0))) : (Math.max(-0, -0x080000000) >>> 0)) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy4, [0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 42, -0x100000000, 0x100000001, -0x080000001, 0x0ffffffff, 0.000000000000001, 0x100000000, 2**53-2, 2**53+2, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000001, -0, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0, -0x080000000, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -1/0, 2**53, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=197; tryItOut("\"use strict\"; t2 = m1.get(f0);");
/*fuzzSeed-209835301*/count=198; tryItOut("mathy0 = (function(x, y) { return (( + (Math.cbrt(( - (Math.imul((y / Number.MAX_VALUE), x) >>> 0))) >>> 0)) == ( + ( + Math.clz32(( ! Math.log((( + Math.sinh(y)) | 0))))))); }); testMathyFunction(mathy0, [-(2**53), -1/0, Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, -Number.MIN_VALUE, 2**53, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, -(2**53+2), 0x0ffffffff, 1, -0x07fffffff, -0x080000001, -(2**53-2), 0/0, -0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, 0x100000001, Number.MAX_VALUE, 0.000000000000001, 0, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=199; tryItOut("a0[x] = 'fafafa'.replace(/a/g, x);");
/*fuzzSeed-209835301*/count=200; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1048577.0;\n    var d3 = -549755813889.0;\n    var d4 = -562949953421312.0;\n    var i5 = 0;\n    {\n      {\n        d2 = (d3);\n      }\n    }\n    i1 = (0x572432e5);\n    return (((0x9957db84)-(((((+abs(((-8388607.0)))) == (8388607.0))) >> (((0x8ca63cc7) ? (-0x8000000) : (0xfc6a97f)))) < (0x7fffffff))))|0;\n    d4 = (-((+(0x4f5c6ff7))));\n    i0 = (0xfa64faa1);\n    {\n      {\n        i5 = (0xfc6bf9d2);\n      }\n    }\n    return ((((0x16cab2fc) ? ((0x9b56eccc)) : (i5))+((0x0) >= (((Float64ArrayView[2]))>>>((0x0) % (0x3ceaa55f))))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [(new Boolean(false)), objectEmulatingUndefined(), [0], (new String('')), ({toString:function(){return '0';}}), '', ({valueOf:function(){return 0;}}), (new Number(-0)), /0/, 1, (new Number(0)), (new Boolean(true)), 0.1, 0, true, (function(){return 0;}), [], '0', ({valueOf:function(){return '0';}}), '/0/', null, '\\0', NaN, -0, undefined, false]); ");
/*fuzzSeed-209835301*/count=201; tryItOut("Array.prototype.pop.call(this.a0);");
/*fuzzSeed-209835301*/count=202; tryItOut("\"use strict\"; ((function ([y]) { })());");
/*fuzzSeed-209835301*/count=203; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, 0.000000000000001, -0x0ffffffff, 2**53-2, 0x080000000, 42, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53+2, -0, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x07fffffff, -0x080000000, 2**53, -(2**53+2), -(2**53), -0x100000001, 1, -Number.MAX_VALUE, 0x080000001, Math.PI, 1/0, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE, -1/0, 0/0, -0x080000001, 0]); ");
/*fuzzSeed-209835301*/count=204; tryItOut("var d = undefined;h0.getOwnPropertyDescriptor = f2;\nv0 = evaluate(\"(c = --e)\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (uneval(6)), sourceIsLazy: Math.min(0, -0), catchTermination: true }));\n");
/*fuzzSeed-209835301*/count=205; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^\", \"gm\"); var s = \"\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=206; tryItOut("uikelb();/*hhh*/function uikelb(window, x = 36028797018963970){v0 = g0.b0.byteLength;}");
/*fuzzSeed-209835301*/count=207; tryItOut("b0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((~~(d1)) < (~~((1152921504606847000.0))));\n    return (((0xfb037737)))|0;\n    return (((0x1a2a98a5)))|0;\n  }\n  return f; });");
/*fuzzSeed-209835301*/count=208; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.imul(Math.sinh((( + ( - Math.fround((Math.atan2((2**53+2 | 0), x) | 0)))) | 0)), (( ! (( + Math.hypot(( + y), ( + y))) >>> 0)) >>> 0)), ( - Math.fround(Math.pow(((y !== y) >>> 0), ((Math.trunc(((( - y) >>> 0) | 0)) | 0) ** ( + (( + y) + ( + Math.ceil(y))))))))); }); testMathyFunction(mathy1, [-(2**53+2), 0/0, Math.PI, -0x07fffffff, -1/0, -0x100000001, 42, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, 0x100000001, -0x0ffffffff, -0x100000000, 0x07fffffff, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 1.7976931348623157e308, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, -(2**53), -0x080000000, 0x100000000, 0x080000001, 2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-209835301*/count=209; tryItOut("\"use strict\"; v2 = new Number(-0);");
/*fuzzSeed-209835301*/count=210; tryItOut("'fafafa'.replace(/a/g, Number.prototype.toExponential);function  (c, x) { ( /x/g ); } \u000creturn;");
/*fuzzSeed-209835301*/count=211; tryItOut("print(uneval(this.g2));");
/*fuzzSeed-209835301*/count=212; tryItOut("\"use strict\"; v0 = Array.prototype.every.call(a1, (function(j) { if (j) { try { m0.delete(e0); } catch(e0) { } try { for (var v of a0) { try { a0.__proto__ = a2; } catch(e0) { } i2.next(); } } catch(e1) { } try { print(this.g2); } catch(e2) { } m0.has(m0); } else { try { v0 = (v0 instanceof s0); } catch(e0) { } try { g0.b1 + ''; } catch(e1) { } try { o1.e1.has(o2.a1); } catch(e2) { } for (var p in f1) { try { h1.valueOf = f1; } catch(e0) { } try { Object.defineProperty(this, \"v1\", { configurable: x, enumerable: true,  get: function() {  return -Infinity; } }); } catch(e1) { } try { g2.b2 = m0.get(t2); } catch(e2) { } v0 = evalcx(\"c &= x\", g2); } } }), o0.o0.i1, f0, x *= x);");
/*fuzzSeed-209835301*/count=213; tryItOut("/*tLoop*/for (let y of /*MARR*/[Number.MIN_VALUE, Number.MIN_VALUE]) { v0 = g0.eval(\"a0.length = 10;\"); }");
/*fuzzSeed-209835301*/count=214; tryItOut("\"use strict\"; testMathyFunction(mathy0, [null, NaN, objectEmulatingUndefined(), [0], 1, ({valueOf:function(){return '0';}}), [], '0', /0/, true, undefined, '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), (new String('')), ({toString:function(){return '0';}}), '/0/', (new Boolean(true)), 0.1, false, 0, (new Number(-0)), (function(){return 0;}), -0, (new Number(0)), '']); ");
/*fuzzSeed-209835301*/count=215; tryItOut("v2 = (f0 instanceof g2.g2.o2);");
/*fuzzSeed-209835301*/count=216; tryItOut("\"use strict\"; print(uneval(p2));");
/*fuzzSeed-209835301*/count=217; tryItOut("if((x % 40 == 37)) /*infloop*/M: for  each(let x in w) L:for(var c in  ) {s1.__iterator__ = (function() { for (var p in t2) { e0.add(g0.o1.e1); } return t1; }); } else  if (0/0.valueOf(\"number\")) {v1 = Object.prototype.isPrototypeOf.call(t2, this.a0);; }");
/*fuzzSeed-209835301*/count=218; tryItOut("/*infloop*/for({x} = neuter; /*UUV2*/(x.getUTCDay = x.toString);  '' ) {f1(a1);print(new true(window, /\\W\\w{4,6}[\\u0001-V\u00b0-\\b\u01c0]|.*?*{3,5}|(?!\\u1334){1,2}/im)); }");
/*fuzzSeed-209835301*/count=219; tryItOut("/*RXUB*/var r = this; var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-209835301*/count=220; tryItOut("/*RXUB*/var r = /\\s|(?!^)/i; var s =  /x/g ; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=221; tryItOut("for (var v of e1) { try { v0 = new Number(o2); } catch(e0) { } try { s1 += 'x'; } catch(e1) { } a2.shift(x); }print(x ? 17 : (uneval(eval)));");
/*fuzzSeed-209835301*/count=222; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.abs((Math.acos(x) | (x , x))) % Math.fround(( + ((Math.exp(((( ~ Math.tanh(Math.round(x))) != (0 > x)) >>> 0)) >>> 0) , (Math.min(Math.min(y, ( + (42 && 0x100000001))), (Math.log(y) | 0)) ? (Math.trunc(x) >>> 0) : ( + (( + (Math.atan((((x | 0) ? ((y <= x) | 0) : (-0x080000000 | 0)) | 0)) | 0)) | ( + (((Math.clz32((Math.log2(y) | 0)) | 0) ? (x >>> 0) : ((Math.fround(Math.log10((-0x100000000 >>> 0))) << x) | 0)) | 0)))))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, -(2**53-2), 2**53, 0/0, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, 0, 2**53+2, -1/0, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, Math.PI, 0x080000000, -(2**53+2), 0x0ffffffff, 42, -0x100000001, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0x100000001, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=223; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.fround(( - ( + Math.log2(( + Math.max(Number.MAX_VALUE, x)))))) - (Math.sin((((((x ? Math.imul(y, y) : Math.fround(( ! x))) >>> 0) > x) >>> 0) | 0)) | 0)), ( - ( + mathy0(( - ((((( + y) !== (y >>> 0)) < -0x0ffffffff) >>> 0) ** x)), ( + ( + Math.max(( + Math.fround(mathy0(Math.fround(y), Math.fround(Math.cbrt(Math.fround(x)))))), ( + y)))))))); }); testMathyFunction(mathy1, [-(2**53+2), 2**53+2, 0x080000000, -0x080000001, 0.000000000000001, 0x080000001, -0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, 2**53, -Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, -(2**53-2), -0x100000000, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, 42, 0x100000001, 1.7976931348623157e308, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1, 0]); ");
/*fuzzSeed-209835301*/count=224; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + ( ! Math.fround(((Math.expm1(y) >>> 0) | Math.sin((mathy2(( + (x << Math.fround(( + -0x080000000)))), (x >>> 0)) | 0)))))); }); testMathyFunction(mathy5, /*MARR*/[eval, (0/0), eval, new Number(1), new Number(1), eval, new Boolean(false), eval, new Boolean(false), new Number(1), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), (0/0), new Boolean(false), (0/0), eval, (0/0), eval, (0/0), eval, eval, new Number(1), new Boolean(false), (0/0), new Number(1), new Number(1), new Number(1), new Boolean(false), eval, new Number(1), new Number(1)]); ");
/*fuzzSeed-209835301*/count=225; tryItOut("\"use strict\"; Object.prototype.unwatch.call(t0, \"getDate\");");
/*fuzzSeed-209835301*/count=226; tryItOut("s1 += s0;");
/*fuzzSeed-209835301*/count=227; tryItOut("yield b;v1 + a2;");
/*fuzzSeed-209835301*/count=228; tryItOut("var qpgocz = new ArrayBuffer(8); var qpgocz_0 = new Int8Array(qpgocz); print(qpgocz_0[0]); var qpgocz_1 = new Float64Array(qpgocz); print(qpgocz_1[0]); var qpgocz_2 = new Uint8ClampedArray(qpgocz); print(qpgocz_2[0]); var qpgocz_3 = new Uint8Array(qpgocz); qpgocz_3[0] = -34359738369; var qpgocz_4 = new Uint32Array(qpgocz); qpgocz_4[0] = -29; var qpgocz_5 = new Float64Array(qpgocz); print(qpgocz_5[0]); qpgocz_5[0] = -0.409; var qpgocz_6 = new Uint16Array(qpgocz); qpgocz_6[0] = window(length, window); var qpgocz_7 = new Int16Array(qpgocz); t2.set(a1, 16);print(qpgocz_5[0]);for (var v of v1) { try { e1 = a2[v2]; } catch(e0) { } try { (void schedulegc(g1)); } catch(e1) { } o1.v2 = t1.length; };/*MXX2*/g0.Math.imul = v2;");
/*fuzzSeed-209835301*/count=229; tryItOut("/*bLoop*/for (let sloyla = 0; sloyla < 36; ++sloyla) { if (sloyla % 5 == 0) { v0 = NaN; } else { v0 = g2.eval(\"mathy2 = (function(x, y) { return Math.fround(( + Math.fround((Math.fround(Math.min(( + Math.fround(Math.fround((x ? ( + -0x0ffffffff) : y)))), ( + ( + Math.imul(Math.atan2(x, x), y))))) ? (Math.tan((( + (( + y) >> ( + (Math.acos((( ! y) | 0)) | 0)))) >>> 0)) , x) : mathy0(mathy1(mathy1(mathy0(x, x), 0x080000000), (((y >>> 0) >>> ((y && 0x080000000) >>> 0)) >>> 0)), Math.pow((y , mathy0(-0x080000000, y)), y)))))); }); testMathyFunction(mathy2, ['', true, (function(){return 0;}), '0', [], ({valueOf:function(){return '0';}}), /0/, ({toString:function(){return '0';}}), undefined, -0, ({valueOf:function(){return 0;}}), 1, false, '\\\\0', (new Number(0)), 0, (new Boolean(true)), '/0/', 0.1, (new Boolean(false)), NaN, (new String('')), objectEmulatingUndefined(), [0], (new Number(-0)), null]); \"); }  } \nprint(o1);\nneuter(b1, \"change-data\");");
/*fuzzSeed-209835301*/count=230; tryItOut("\"use strict\"; print(v1);");
/*fuzzSeed-209835301*/count=231; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ~ ((( ! (mathy3((Math.fround(Math.min(( + Math.acosh(( + y))), ((Math.fround(x) , Math.fround(y)) >>> 0))) | 0), (-0 | 0)) | 0)) - (((y | 0) ** (Math.fround(Math.pow(Math.atan2(-Number.MAX_VALUE, (y >>> 0)), Math.fround(Math.ceil((-Number.MIN_SAFE_INTEGER | 0))))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x080000000, 0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, 2**53, -1/0, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 1.7976931348623157e308, -0x100000001, 2**53+2, -(2**53-2), -0x100000000, -0x080000001, 0, 0x080000000, 0x100000001, -0x0ffffffff, 1/0, 2**53-2, 1, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-209835301*/count=232; tryItOut("\"use strict\"; v1 = false\n");
/*fuzzSeed-209835301*/count=233; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy0((Math.acosh((-1/0 | 0)) | 0), ((( + (y | 0)) >>> 0) + -(2**53-2))) ? Math.atan2((Math.hypot((Math.min((Math.fround(( - Math.fround(y))) >>> 0), Math.fround(Math.tanh(-0x100000001))) >>> 0), ((Math.fround(Math.hypot(Math.fround(Math.fround(Math.max(( + x), Math.fround(( ! y))))), Math.fround((( + Math.min(0x07fffffff, 42)) * -0x080000001)))) >>> 0) % x)) | 0), Math.fround((Math.hypot((( ~ Math.imul(( + Math.pow(( + y), (y | 0))), x)) | 0), (( + ( ~ ( + (( + ( + ((x >>> 0) / ( + x)))) < y)))) && ( + Math.cos(( + Math.sign(2**53+2)))))) | 0))) : Math.tan(((( ~ x) >>> 0) >= Math.hypot(Math.cosh(Math.max(( + x), ( + -Number.MAX_SAFE_INTEGER))), ( ! x))))); }); testMathyFunction(mathy2, [0x080000001, 0/0, 42, -1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0, 0x07fffffff, -(2**53+2), 0x100000000, 0.000000000000001, -(2**53), -Number.MAX_VALUE, -(2**53-2), 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, -0x0ffffffff, -0x080000000, -0x100000001, 2**53+2, 0x0ffffffff, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 1, 0x080000000]); ");
/*fuzzSeed-209835301*/count=234; tryItOut("g0.m1 = new WeakMap;");
/*fuzzSeed-209835301*/count=235; tryItOut("\"use asm\"; var vhfhtr = new SharedArrayBuffer(8); var vhfhtr_0 = new Uint8ClampedArray(vhfhtr); vhfhtr_0[0] = {} = x; var vhfhtr_1 = new Uint32Array(vhfhtr); print(vhfhtr_1[0]); var vhfhtr_2 = new Uint16Array(vhfhtr); var vhfhtr_3 = new Int32Array(vhfhtr); var vhfhtr_4 = new Uint16Array(vhfhtr); vhfhtr_4[0] = 28; var vhfhtr_5 = new Float64Array(vhfhtr); vhfhtr_5[0] = -6; t1[8] = e1;v1 = (this.a2 instanceof m1);m2.set(h0, this.a0);");
/*fuzzSeed-209835301*/count=236; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: (x % 6 == 1), enumerable: false,  get: function() {  return g0.eval(\"\\\"use strict\\\"; testMathyFunction(mathy1, [1.7976931348623157e308, 0x080000000, 2**53+2, 0x100000000, 1, 0x080000001, 0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -(2**53), -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, Math.PI, 42, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, -1/0, 0, -0, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, -0x080000001, -(2**53-2), 0/0, 1/0, 0.000000000000001, 0x0ffffffff]); \"); } });");
/*fuzzSeed-209835301*/count=237; tryItOut("\"use strict\"; v2 = evaluate(\"function f0(m1)  { return Math.max(17, [[1]]) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: ({[]: (void options('strict')) }), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-209835301*/count=238; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.sinh((((( + ( - ( + Math.atan2(Math.pow((2**53+2 % y), Number.MIN_SAFE_INTEGER), y)))) | 0) << (((Math.fround(Math.log(x)) | 0) ^ (Math.exp(Math.atan2(((x | 0) ? (-Number.MIN_SAFE_INTEGER | 0) : -0x100000001), 2**53)) | 0)) | 0)) | 0))); }); testMathyFunction(mathy0, [-0x0ffffffff, 0/0, -0x100000000, -0x080000001, 1/0, -(2**53-2), -0x07fffffff, 2**53-2, -Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, Math.PI, 1, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, -(2**53), 0, -Number.MIN_VALUE, 0x100000001, -1/0, Number.MAX_VALUE, 2**53+2, -0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, 0x07fffffff, 42, -0, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=239; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.atan(Math.fround(((x && ((( ~ (0x07fffffff ^ x)) >>> 0) | 0)) + Math.fround(Math.clz32((Math.min((y - Math.fround(y)), ( + y)) >>> 0))))))); }); testMathyFunction(mathy5, [0.1, [], /0/, objectEmulatingUndefined(), '0', (new String('')), true, 0, ({valueOf:function(){return '0';}}), (new Number(0)), (function(){return 0;}), '/0/', (new Boolean(true)), [0], 1, undefined, false, null, -0, ({valueOf:function(){return 0;}}), NaN, ({toString:function(){return '0';}}), (new Number(-0)), '', (new Boolean(false)), '\\0']); ");
/*fuzzSeed-209835301*/count=240; tryItOut("print(arguments);");
/*fuzzSeed-209835301*/count=241; tryItOut("mathy2 = (function(x, y) { return Math.tan(Math.fround(( ~ Math.fround(Math.fround(Math.sinh(( + (Math.cbrt(((( + 42) | 0) | 0)) | 0)))))))); }); testMathyFunction(mathy2, [0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 0x080000001, -0x100000000, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 42, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, 0, -(2**53+2), 1, 2**53, 0/0, -Number.MIN_VALUE, 2**53+2, Number.MIN_VALUE, 0.000000000000001, -1/0, 2**53-2, Number.MAX_VALUE, -0]); ");
/*fuzzSeed-209835301*/count=242; tryItOut("let (NaN = x, elxumd, x = x, b = new ( /x/g  << 7)([,], /./yim)) x;");
/*fuzzSeed-209835301*/count=243; tryItOut("testMathyFunction(mathy5, [0.000000000000001, 42, 0x100000000, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -0x100000001, -(2**53-2), 0, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, -0x07fffffff, 2**53-2, Math.PI, -0x080000001, 0/0, 0x100000001, -(2**53), 2**53+2, -0x0ffffffff, 1/0, -0, -Number.MAX_VALUE, -1/0, -(2**53+2), 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-209835301*/count=244; tryItOut("for (var p in e2) { try { for (var v of f2) { try { a0 = Array.prototype.concat.call(a0); } catch(e0) { } try { a2 = a0.slice(-11, -4); } catch(e1) { } try { h0.fix = (function() { try { o2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i0);\n    }\n    return ((-0xb648b*((0x7fffffff))))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; v1 = t1.length;; yield y; }}, new ArrayBuffer(4096)); } catch(e0) { } try { v1 = o0.g0.g2.runOffThreadScript(); } catch(e1) { } try { e0.toSource = (function mcc_() { var pnhjyo = 0; return function() { ++pnhjyo; if (/*ICCD*/pnhjyo % 6 == 1) { dumpln('hit!'); /*ODP-3*/Object.defineProperty(h1, \"__count__\", { configurable: (x % 4 == 2), enumerable: (x % 5 == 2), writable: true, value: window }); } else { dumpln('miss!'); try { t2 = new Uint16Array(b1, 15, 19); } catch(e0) { } try { Array.prototype.reverse.apply(a1, []); } catch(e1) { } try { v0 = a2.every((function(j) { if (j) { try { a1.pop(v1); } catch(e0) { } try { b2 = t0[v1]; } catch(e1) { } h0.valueOf = f2; } else { f0.valueOf = f2; } })); } catch(e2) { } this.v0 = a1.reduce, reduceRight(function(y) { (window); }, g2, s1, this.s2, h0, v1, p2); } };})(); } catch(e2) { } t1 = new Float32Array(b2); return p2; }); } catch(e2) { } g0.v0 = Object.prototype.isPrototypeOf.call(a2, b2); } } catch(e0) { } v0 = evaluate(\"i2.send(t0);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: window, noScriptRval: (x % 48 == 10), sourceIsLazy: true, catchTermination: true, sourceMapURL: s2 })); }");
/*fuzzSeed-209835301*/count=245; tryItOut("\"use strict\"; Array.prototype.push.call(g0.a2, o0, f2, i2);");
/*fuzzSeed-209835301*/count=246; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - ( + (( + Math.cosh(42)) >= Math.fround(Math.atan2((( + ( ~ Number.MAX_VALUE)) << (x | 0)), ( + ( - (mathy0(x, -(2**53-2)) | 0)))))))) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[(void 0), (void 0), null, null, x, null, (void 0), new Number(1), (void 0), new Number(1), null, x, (void 0), x, (void 0), x, new Number(1), (void 0), null, x, null, new Number(1), null, null, x, new Number(1), x, null, new Number(1), new Number(1), x, new Number(1), (void 0), (void 0), x, (void 0), new Number(1), x, x, (void 0), x, new Number(1), null, x, (void 0), new Number(1), new Number(1), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), x, null, null, (void 0), x, new Number(1), x, x, x, x, null, x, new Number(1), null, x, (void 0), new Number(1), new Number(1)]); ");
/*fuzzSeed-209835301*/count=247; tryItOut("\"use strict\"; for (var v of g1) { try { /*ADP-3*/Object.defineProperty(a1, 9, { configurable: false, enumerable: false, writable: (x % 5 == 4), value: x }); } catch(e0) { } a0.unshift(g1, a0, m2, f0); }");
/*fuzzSeed-209835301*/count=248; tryItOut("\"use strict\"; /*bLoop*/for (let fgnpww = 0; fgnpww < 25; ++fgnpww) { if (fgnpww % 34 == 31) { /*RXUB*/var r = r2; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex);  } else { print(-10); }  } ");
/*fuzzSeed-209835301*/count=249; tryItOut("mathy4 = (function(x, y) { return Math.atanh(mathy1(Math.ceil(Math.fround(Math.sqrt(-(2**53+2)))), Math.imul(Math.atan2((y | 0), (y | 0)), (y | 0)))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -(2**53), -1/0, -(2**53-2), Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, -0x0ffffffff, 0/0, -0, 0x0ffffffff, 1/0, -0x100000001, 0x07fffffff, Number.MIN_VALUE, 42, 2**53-2, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, -0x080000000, 0x080000000, -0x100000000, -0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 2**53+2, 0, 0.000000000000001, 1.7976931348623157e308, 1]); ");
/*fuzzSeed-209835301*/count=250; tryItOut("s2 += 'x';");
/*fuzzSeed-209835301*/count=251; tryItOut("var vdakls = new ArrayBuffer(0); var vdakls_0 = new Float64Array(vdakls); vdakls_0[0] = 23; var vdakls_1 = new Uint32Array(vdakls); print(vdakls_1[0]); vdakls_1[0] = -3; for (var p in i0) { try { v2 = (o2 instanceof h1); } catch(e0) { } try { h2.iterate = (function() { try { /*MXX3*/g2.Object.prototype.__proto__ = g0.Object.prototype.__proto__; } catch(e0) { } g0.v1 = t0.BYTES_PER_ELEMENT; return e2; }); } catch(e1) { } try { g1.v0 = true; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(this.a1, b1); }Array.prototype.pop.call(a0);\no1.i0.next();\n");
/*fuzzSeed-209835301*/count=252; tryItOut("\"use strict\"; v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { t2.set(t1, 18); return o1.p1; }), o1.p1, g1.o0.p0]);");
/*fuzzSeed-209835301*/count=253; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.pow(( + Math.min((Math.fround((Math.fround(Math.fround((Math.fround(y) % ( + 2**53+2)))) ** x)) | 0), ( + (x === (((Math.sqrt(Math.imul(y, ( + y))) >>> 0) | 0) ** (((mathy0(y, y) >>> 0) <= 42) >>> 0)))))), Math.sin((Math.fround(mathy0((( ! Math.fround(x)) >>> 0), (y % x))) ? ( + Math.fround(Math.acos(((Math.fround(y) !== x) | 0)))) : ((((Number.MAX_VALUE < 2**53) >>> 0) && ((Math.fround(( ! Math.fround(mathy0((x >>> 0), (y | 0))))) ^ (((y >>> 0) > (y >>> 0)) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[function(){}, false, false, false, function(){}, false, false, function(){}, function(){}, function(){}, false, function(){}, function(){}, false, function(){}, function(){}, false, function(){}, function(){}, function(){}, false, false, function(){}, function(){}, false, false, function(){}, function(){}, false, function(){}, function(){}, false, function(){}, false, function(){}, false, false, false, function(){}, false, function(){}, false, false, function(){}, false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, false, function(){}, false, function(){}, function(){}, function(){}, false, function(){}, false, false, false, function(){}, function(){}, false, function(){}, false, false, function(){}, false, false, function(){}, false, false, function(){}, function(){}, function(){}, false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, false, false, function(){}, false, function(){}, function(){}, false, function(){}]); ");
/*fuzzSeed-209835301*/count=254; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (i0);\n    }\n    d1 = (+atan2(((-140737488355327.0)), ((+(-1.0/0.0)))));\n    i0 = (0x35eed9dc);\n    return +((1.00390625));\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 1, 0.000000000000001, Math.PI, 1.7976931348623157e308, -0x0ffffffff, -0x080000001, 0, 2**53-2, 0x0ffffffff, 2**53+2, 2**53, Number.MAX_VALUE, 0x100000000, -0x100000001, 42, Number.MIN_VALUE, -0x080000000, 0x100000001, -(2**53+2), -0x07fffffff, -0x100000000, -(2**53), 0/0, 0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=255; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot(Math.ceil((Math.min(Math.fround((Math.max((x >>> 0), Math.fround(( ~ x))) >>> 0)), Math.atan2(((y > y) | 0), y)) >>> 0)), ( + Math.min(Math.fround(( - Math.fround(( + y)))), (Math.imul(( + ( + Math.imul((y != Math.max(y, Math.fround(-0x100000001))), (Math.pow(x, x) >>> 0)))), 0x100000001) | 0)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), -0, Number.MIN_VALUE, 0, -1/0, -(2**53-2), 1, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 42, 2**53+2, -0x0ffffffff, 0x080000001, 0x100000000, 2**53-2, -0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 0x07fffffff, Math.PI, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, 0.000000000000001, 2**53, 0/0, 0x100000001]); ");
/*fuzzSeed-209835301*/count=256; tryItOut("a2.pop(g1.h0);");
/*fuzzSeed-209835301*/count=257; tryItOut("\"use strict\"; /*infloop*/for(var x(\"\u03a0\") in (((new Function(\"i2.next();\")))(intern(((uneval( \"\" ))))))){m1.get(f2); }");
/*fuzzSeed-209835301*/count=258; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( + Math.hypot(( + (-0 >>> Math.atan2((Math.abs((( + Math.PI) >>> 0)) | 0), ( ~ (Math.hypot((y >>> 0), (y | 0)) >>> 0))))), ( + Math.min(Math.atanh((Math.min(y, -(2**53-2)) | 0)), ( + (( + ((y | 0) | (y | 0))) ? Math.fround(Math.fround(Math.pow(Math.fround(( + Math.hypot(( + ( + Math.log1p(y))), ( + (x <= y))))), y))) : ( + -0x100000001))))))) ? Math.sign(Math.imul(Math.atan2(Math.sqrt(2**53-2), ( ~ Math.fround(0x080000001))), Math.fround(( ~ Math.fround((( ! (-(2**53+2) | 0)) | 0)))))) : (( ! ( - Math.tanh((Number.MAX_VALUE === (-0x080000000 | 0))))) >>> 0)); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, -0x100000001, 2**53-2, 0x0ffffffff, -0x080000000, 2**53+2, 0/0, -0, 0x080000000, 1.7976931348623157e308, 1, -Number.MAX_SAFE_INTEGER, -1/0, 1/0, -0x100000000, 0x080000001, 42, Number.MIN_VALUE, -(2**53-2), 0x100000001, -0x07fffffff, -(2**53+2), -0x080000001, Math.PI, 0x07fffffff, 0, -(2**53), 0x100000000]); ");
/*fuzzSeed-209835301*/count=259; tryItOut("mathy1 = (function(x, y) { return Math.imul(Math.fround((( + mathy0(( + (mathy0((Math.log(Math.fround(Math.asinh(Math.PI))) | 0), Math.min(Math.log10(x), y)) | 0)), (Math.fround(Math.round(Math.atan(Math.fround(Math.pow((x >>> 0), Math.fround(y)))))) | 0))) < (( + (Math.min(Math.fround((Math.fround(Math.PI) >> y)), ((( + (mathy0(x, 0x080000001) >>> 0)) >>> 0) | 0)) | 0)) % 0/0))), (Math.sign((Math.cosh(Math.fround((( + Math.fround((Math.fround(y) == Math.fround(y)))) !== y))) | 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[(-1/0), arguments.callee, false, false, arguments.callee, (-1/0), false, arguments.callee, (-1/0), arguments.callee, arguments.callee, (-1/0), false, arguments.callee, arguments.callee, (-1/0), arguments.callee, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, arguments.callee, (-1/0), false, arguments.callee, (-1/0), (-1/0), (-1/0), false, (-1/0), false, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, (-1/0), (-1/0), false, (-1/0)]); ");
/*fuzzSeed-209835301*/count=260; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 2147483649.0;\n    (Uint16ArrayView[((i2)) >> 1]) = (((((d1) == (d1))) >> ((0xf9fbbe45)*-0xf8e9c)) % (imul((0xf8ae9865), ((i0) ? (i3) : (i2)))|0));\n    d1 = (68719476737.0);\n    d1 = (Infinity);\n    return (((0xfba92a72)-((+((140737488355328.0))) != (((+(1.0/0.0))) - ((d1))))))|0;\n  }\n  return f; })(this, {ff: Math.fround}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[[],  '\\0' , [], [], objectEmulatingUndefined(), objectEmulatingUndefined(), [],  '\\0' , objectEmulatingUndefined(), [],  '\\0' , [], [], [], [], [], objectEmulatingUndefined(),  '\\0' ,  '\\0' , objectEmulatingUndefined(),  '\\0' ,  '\\0' , [],  '\\0' , [], objectEmulatingUndefined(),  '\\0' ,  '\\0' , [],  '\\0' ,  '\\0' , [],  '\\0' , [], [],  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), [], [],  '\\0' , [], [], [], objectEmulatingUndefined(), [], objectEmulatingUndefined(),  '\\0' , [], objectEmulatingUndefined(), [], [],  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(),  '\\0' , [], [], objectEmulatingUndefined(), [],  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [], objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), [], [], [], [], [], [], [], [], [], [], []]); ");
/*fuzzSeed-209835301*/count=261; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.atan2(Math.fround(Math.fround(mathy0(Math.fround((\"\\u0044\" = \"\\u020A\" ? y : ((((Math.asin(x) | 0) ^ Math.clz32(Math.fround(y))) | 0) >>> 0))), ( + x)))), (((Math.atan2((x >>> 0), (Math.cosh((-1/0 >>> 0)) >>> 0)) >>> 0) === ( + ( + 0))) >>> 0)) >> (((( + ( + Math.abs(x))) + (Math.tanh((( - y) | 0)) | 0)) <= (((Math.hypot((( + ( + Math.sign(-Number.MIN_VALUE))) >>> 0), (( + Math.sqrt(1)) >>> 0)) >>> 0) | 0) >= ( + (((-0 && y) >>> 0) | (y ? (x ? Math.expm1(Math.fround(x)) : y) : y))))) | 0)); }); testMathyFunction(mathy3, [0, '0', ({valueOf:function(){return '0';}}), (new Number(0)), NaN, (function(){return 0;}), false, -0, '\\0', ({valueOf:function(){return 0;}}), (new Boolean(true)), '/0/', [0], ({toString:function(){return '0';}}), 0.1, 1, (new String('')), '', undefined, /0/, [], (new Boolean(false)), (new Number(-0)), objectEmulatingUndefined(), true, null]); ");
/*fuzzSeed-209835301*/count=262; tryItOut("h1.toSource = (function() { for (var j=0;j<1;++j) { f0(j%5==1); } });");
/*fuzzSeed-209835301*/count=263; tryItOut("\"use strict\"; v0 = (x % 11 != 6);");
/*fuzzSeed-209835301*/count=264; tryItOut("v2 = (i0 instanceof o0.e2);");
/*fuzzSeed-209835301*/count=265; tryItOut("this.e0.has(v2);");
/*fuzzSeed-209835301*/count=266; tryItOut("s2 = new String;");
/*fuzzSeed-209835301*/count=267; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.imul((Math.cos(((y || (-Number.MAX_VALUE | 0)) | 0)) | 0), Math.fround(((y == x) ? ( + Math.min((x >> x), x)) : ( + x)))) ** ( + Math.fround(Math.imul(( - ( ! x)), (Math.trunc(( + Math.atan2(Math.fround(y), (y | 0)))) | 0))))); }); testMathyFunction(mathy3, [0, 0x07fffffff, 42, Math.PI, 2**53+2, -0x0ffffffff, -(2**53), 0x0ffffffff, -0, 1, -(2**53+2), 0x080000001, -Number.MAX_VALUE, -(2**53-2), -0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, 1.7976931348623157e308, 0.000000000000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 0/0, 1/0, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=268; tryItOut("v0 = this.r2.test;");
/*fuzzSeed-209835301*/count=269; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=270; tryItOut("/*tLoop*/for (let b of /*MARR*/[new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined()]) { /*oLoop*/for (let giipyh = 0; giipyh < 130; ++giipyh) { s2 += 'x'; }  }");
/*fuzzSeed-209835301*/count=271; tryItOut("\"use strict\"; g0.__proto__ = h0;");
/*fuzzSeed-209835301*/count=272; tryItOut("testMathyFunction(mathy4, [-0x080000000, -(2**53-2), 0/0, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, Math.PI, 2**53-2, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x0ffffffff, 1, 0, -(2**53), -0, 2**53+2, -0x100000001, 0x100000000, -(2**53+2), Number.MAX_VALUE, 0x080000001, 0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 2**53, -0x080000001, 0x100000001]); ");
/*fuzzSeed-209835301*/count=273; tryItOut("\"use asm\"; ");
/*fuzzSeed-209835301*/count=274; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(mathy0(Math.fround(mathy0(Math.fround(Math.atan(-(2**53))), Math.fround((Math.imul(( + -(2**53-2)), -Number.MIN_SAFE_INTEGER) >>> 0)))), (Math.max(x, -1/0) <= ( + mathy1(x, ( + mathy0(( + y), ( + y))))))))); }); testMathyFunction(mathy2, /*MARR*/[(0/0), -Infinity, function(){}]); ");
/*fuzzSeed-209835301*/count=275; tryItOut("p1.toSource = (function mcc_() { var xxpilz = 0; return function() { ++xxpilz; if (/*ICCD*/xxpilz % 6 == 0) { dumpln('hit!'); try { /*MXX1*/var o1 = g1.DataView.prototype.getInt8; } catch(e0) { } try { for (var p in a0) { try { Object.defineProperty(this, \"this.v0\", { configurable: true, enumerable: true,  get: function() { v2 = t2.byteOffset; return t1.byteOffset; } }); } catch(e0) { } try { a0.sort((function(j) { o2.f1(j); })); } catch(e1) { } g2.i0.next(); } } catch(e1) { } try { v1 = a2.length; } catch(e2) { } b0 = new ArrayBuffer(7); } else { dumpln('miss!'); try { e0 + this.i1; } catch(e0) { } try { this.v1 = false; } catch(e1) { } try { o0 = new Object; } catch(e2) { } print(v1); } };})();");
/*fuzzSeed-209835301*/count=276; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=277; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.trunc(Math.fround(( + ( ! (((Math.hypot(y, y) >>> 0) ** (( ~ Math.abs(y)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, -0x080000001, -0x07fffffff, 0/0, 0, -0, 1.7976931348623157e308, 2**53+2, -1/0, 0.000000000000001, Number.MAX_VALUE, 0x080000001, -0x100000000, 42, 1, -(2**53+2), 0x100000000, 0x080000000, -0x080000000, 1/0, 0x07fffffff, 0x100000001, -(2**53)]); ");
/*fuzzSeed-209835301*/count=278; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use asm\"; return Math.fround(Math.atan2(Math.cbrt((Math.fround(y) ? x : (y >>> 0))), ( + (( + (( ~ (( - (( + Math.fround(mathy1((Math.fround(Math.log2(Math.fround(x))) | 0), (Math.fround((y + (y | 0))) | 0)))) >>> 0)) | 0)) | 0)) ? ( + Math.hypot(Math.atan2((Math.imul(Math.min(1, (Math.max((-Number.MAX_VALUE | 0), (x | 0)) | 0)), ((2**53-2 * mathy1(-Number.MAX_VALUE, y)) | 0)) >>> 0), Math.fround(y)), (Math.log(Math.asinh((((Math.fround(( ! Math.fround(0))) | 0) ? (-Number.MIN_VALUE | 0) : (( ~ x) | 0)) | 0))) >>> 0))) : ( + ((((mathy0((Math.sinh((Math.acosh(( + x)) | 0)) >>> 0), ((x % ((Math.atanh((( - x) >>> 0)) >>> 0) | 0)) >>> 0)) >>> 0) >>> 0) ? ((( + y) >= ((y != (-(2**53+2) ? y : y)) >>> 0)) >>> 0) : (Math.fround((Math.fround(y) >= Math.fround(( ! y)))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [0, -(2**53), 0x080000000, Math.PI, 0x080000001, 0x100000001, 2**53-2, 42, 0x100000000, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, 1.7976931348623157e308, -0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, Number.MIN_VALUE, 1/0, 1, 2**53, -0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53+2), -0x080000000, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=279; tryItOut("mathy4 = (function(x, y) { return (( ~ (( + Math.trunc((( ! ( ~ Math.fround(Math.max(Math.fround(Math.fround(Math.trunc(( + x)))), x)))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy4, ['0', NaN, 0, /0/, (new Number(0)), [0], '\\0', (new Boolean(true)), ({valueOf:function(){return '0';}}), '/0/', undefined, ({valueOf:function(){return 0;}}), (new Number(-0)), (new Boolean(false)), -0, objectEmulatingUndefined(), (new String('')), (function(){return 0;}), 0.1, 1, false, true, ({toString:function(){return '0';}}), [], null, '']); ");
/*fuzzSeed-209835301*/count=280; tryItOut("\"use strict\"; L:switch(x =  /x/ ) { default: print(x);case 9: break;  }");
/*fuzzSeed-209835301*/count=281; tryItOut("for (var p in m0) { try { v0 = Object.prototype.isPrototypeOf.call(m1, g0.o1); } catch(e0) { } try { i1.next(); } catch(e1) { } try { Array.prototype.unshift.call(a0, s0, this.f2, e2, 29); } catch(e2) { } /*RXUB*/var r = this.r0; var s = s2; print(uneval(r.exec(s)));  }");
/*fuzzSeed-209835301*/count=282; tryItOut("var ngtisx = new ArrayBuffer(12); var ngtisx_0 = new Int8Array(ngtisx); print(ngtisx_0[0]); a2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = ((('fafafa'.replace(/a/g, encodeURIComponent))) / (((allocationMarker() === Number.MIN_SAFE_INTEGER))));\n    d1 = (-2147483649.0);\n    return ((((imul((i0), ((((0xfbe1c2e5)) >> (((((0xfeeee747))|0))+(0xfd5200c2)))))|0) >= (((i0)*-0x52dc0) << ((0xc91e4081)-(!(/*FFI*/ff()|0)))))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096));t2.set(t2,  '' );print(v0);a0.splice(-2, 15, t1);");
/*fuzzSeed-209835301*/count=283; tryItOut("( /x/ );");
/*fuzzSeed-209835301*/count=284; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-209835301*/count=285; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return Math.max(Math.log(( + Math.fround(((( ~ ( + ( - x))) ? (-0x080000001 >>> 0) : (y ? y : y)) >>> 0)))), ( + Math.sin(( + (Math.max(Math.cbrt(((x | Math.pow((x >>> 0), -Number.MAX_SAFE_INTEGER)) >>> 0)), Math.min(-Number.MAX_SAFE_INTEGER, x)) >= (Math.acos((( + x) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy1, [0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, 0x0ffffffff, 0x080000001, 42, 0/0, 1/0, 0.000000000000001, -0x0ffffffff, 2**53, -Number.MIN_VALUE, 0x080000000, -0x080000001, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, Math.PI, -(2**53-2), 0x100000001, -0x100000001, -0x080000000, 0, 2**53-2, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=286; tryItOut("testMathyFunction(mathy2, [-0x080000001, 42, Number.MAX_VALUE, 0x100000000, 0x0ffffffff, Math.PI, -0x080000000, 0x07fffffff, -1/0, Number.MIN_VALUE, 1, 0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 1/0, 2**53+2, 0x080000001, 0.000000000000001, -0x100000001, 2**53-2, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, -(2**53), -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 0, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=287; tryItOut("\"use strict\"; /*oLoop*/for (var jdjxfu = 0; jdjxfu < 74; new RegExp(\"(\\\\b)\", \"i\"), ++jdjxfu) { v2 = Object.prototype.isPrototypeOf.call(s1, e1); } ");
/*fuzzSeed-209835301*/count=288; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, -1/0, -0, -Number.MAX_VALUE, -0x100000001, 1/0, 0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, -0x080000001, -(2**53-2), Math.PI, 2**53, 0x080000001, 0, 2**53-2, 0/0, 0x07fffffff, -0x100000000, 2**53+2, -0x080000000, -0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=289; tryItOut("/*RXUB*/var r = /(?:(\\W|${4}|\\x70.?+?)*?\\2(?!.{3,})){2,}/i; var s = \"\"; print(s.replace(r, (1 for (x in [])), \"yim\")); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=290; tryItOut("\"use asm\"; m2.delete(b0);");
/*fuzzSeed-209835301*/count=291; tryItOut("/*MXX1*/o2 = g2.String.prototype.bold;");
/*fuzzSeed-209835301*/count=292; tryItOut("print((w < x));");
/*fuzzSeed-209835301*/count=293; tryItOut("\"use strict\"; for (var v of t1) { try { m2.set(e1, i1); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(a2, h0); } catch(e1) { } a2[7]; }");
/*fuzzSeed-209835301*/count=294; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return ((((( ! ((x << x) >>> 0)) | 0) >>> 0) + (Math.max(((Math.fround(Math.trunc(( - 0x080000000))) ? (Math.max((Math.imul(y, Math.hypot(y, ( + y))) | 0), ((x !== (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)) | 0) : Math.fround(x)) | 0), (x == Math.fround(Math.max(mathy1(( + y), Math.max(-Number.MAX_VALUE, y)), Math.fround((Math.hypot((y >>> 0), (x >>> 0)) >>> 0)))))) | 0)) >>> 0); }); ");
/*fuzzSeed-209835301*/count=295; tryItOut("\"use strict\"; s2 += g1.s1;");
/*fuzzSeed-209835301*/count=296; tryItOut("mathy1 = (function(x, y) { return ( - Math.acos((Math.atan2(y, ((((x | 0) >>> -(2**53)) >= x) | 0)) >>> 0))); }); ");
/*fuzzSeed-209835301*/count=297; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy2((Math.min(( + ( ! mathy2((y >>> 0), Number.MIN_SAFE_INTEGER))), ( - mathy1((Math.imul(((x ? (y | 0) : x) >>> 0), (Math.pow((((x | 0) !== (x | 0)) | 0), y) | 0)) | 0), ((Math.atan2(x, x) | 0) >>> 0)))) | 0), (mathy2((Math.cbrt(( - ( + (Math.acos((2**53 | 0)) | 0)))) | 0), (( + Math.log10(( + x))) << ( + 0x080000000))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[x, (-1/0), objectEmulatingUndefined(), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, objectEmulatingUndefined(), (-1/0), (-1/0), (-1/0), (-1/0), x, objectEmulatingUndefined(), (-1/0), [1], true, (-1/0), (-1/0), [1], (-1/0), true, true, (-1/0), objectEmulatingUndefined(), true, [1], [1], x, x, (-1/0), true, objectEmulatingUndefined(), x, (-1/0), (-1/0), x, [1], x, true, x, [1], true, objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), true, true, (-1/0), [1], x, x, x, x, x, x, x, x, [1], x, [1], objectEmulatingUndefined(), true, x]); ");
/*fuzzSeed-209835301*/count=298; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - (( + (( + (mathy2((mathy0(Math.log(mathy1(x, x)), y) >>> 0), (y >>> 0)) >>> 0)) ? ( + ( ! Math.fround(( - (( + Math.atanh((x >>> 0))) >>> 0))))) : ( + ( + Math.sinh(( + ( + mathy2(Math.fround(Math.hypot(x, x)), ( + Math.log2(Math.pow(-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER))))))))))) >>> 0)); }); ");
/*fuzzSeed-209835301*/count=299; tryItOut("t0[6];");
/*fuzzSeed-209835301*/count=300; tryItOut("\"use strict\"; b1 + g1;w = x;");
/*fuzzSeed-209835301*/count=301; tryItOut("\"use strict\"; /*vLoop*/for (mtgadk = 0; mtgadk < 34; ++mtgadk, (/*MARR*/[undefined, undefined, objectEmulatingUndefined(), x, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, x, undefined, {}, x, undefined, objectEmulatingUndefined(), -0xB504F332, objectEmulatingUndefined(), x, {}, {}, x, {}, undefined, -0xB504F332, {}, undefined, x, objectEmulatingUndefined(), -0xB504F332, {}, -0xB504F332, objectEmulatingUndefined(), -0xB504F332, {}, objectEmulatingUndefined(), {}, undefined, -0xB504F332, -0xB504F332, undefined, {}, objectEmulatingUndefined(), x, undefined, {}, undefined, {}, objectEmulatingUndefined(), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, undefined, x, -0xB504F332, undefined, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), {}, -0xB504F332, -0xB504F332, objectEmulatingUndefined(), -0xB504F332, x, undefined, -0xB504F332, {}, {}, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), -0xB504F332, -0xB504F332, -0xB504F332, {}, objectEmulatingUndefined(), -0xB504F332, x, undefined, x, x, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, -0xB504F332, x, {}, -0xB504F332, -0xB504F332, {}, undefined, -0xB504F332, objectEmulatingUndefined(), x, -0xB504F332, undefined, undefined, -0xB504F332, x, -0xB504F332, undefined, objectEmulatingUndefined(), -0xB504F332, {}, {}, {}, -0xB504F332, -0xB504F332, undefined, -0xB504F332, x, objectEmulatingUndefined(), undefined, x, {}, x, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, {}, objectEmulatingUndefined(), undefined, -0xB504F332, {}, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, -0xB504F332, objectEmulatingUndefined()].map(c =>  { v1 = t1.length; } ))) { let c = mtgadk; /* no regression tests found */ } ");
/*fuzzSeed-209835301*/count=302; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 3.022314549036573e+23;\n    i0 = (!(false));\n    (Int32ArrayView[1]) = (((((i1)) << (-0xb3aab*(i0))) <= (0x6e38ca79)));\n    (Uint32ArrayView[(((((-0x8000000)-(i1))>>>((0x820ff3e2)+(-0x8000000)+(0x428e3b6))))+(0xffffffff)) >> 2]) = (-0x140b6*(((((0x536ee306))|0)) ? (0x95756fa6) : (i1)));\n    {\n      (Float64ArrayView[4096]) = ((1.125));\n    }\n    {\n      i1 = ((-(((Date.prototype.getHours).call((4277), )))) >= (d2));\n    }\n    return +((+abs(((-2049.0)))));\n  }\n  return f; })(this, {ff: arguments.callee.caller.caller}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=303; tryItOut("v2 = t0.byteOffset;");
/*fuzzSeed-209835301*/count=304; tryItOut("let (y) { throw y; }");
/*fuzzSeed-209835301*/count=305; tryItOut("v2 = g0.eval(\"t1 = m1.get(g0);\");");
/*fuzzSeed-209835301*/count=306; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy3(( + (mathy3((Math.fround(Math.imul((Math.fround(Math.pow(x, Math.fround((( ~ (Math.fround(( + ( + Math.hypot(Math.fround(2**53), Math.fround(x))))) >>> 0)) >>> 0)))) >>> 0), Math.fround(Math.fround(Math.acosh(Math.fround(( ! (((y >>> 0) ** (Math.imul(( + y), y) >>> 0)) >>> 0)))))))) >>> 0), (Math.hypot((Math.tanh((Math.sqrt(Math.fround(Math.pow(2**53, x))) >>> 0)) >>> 0), ( ! ( + ((((x | 0) <= y) | 0) == ( + ( + mathy2(( + mathy4(2**53+2, x)), (-0 | 0)))))))) >>> 0)) >>> 0)), ( ! ( - Math.fround(Math.atanh(( + (y & (Math.min((1/0 | 0), (x | 0)) | 0)))))))) >>> 0); }); testMathyFunction(mathy5, [0x100000000, 2**53+2, -0x080000000, -0x100000000, 0x07fffffff, 0/0, 0x080000000, -0x07fffffff, -0x080000001, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, -(2**53+2), -(2**53-2), -0, Math.PI, 0x0ffffffff, 0x100000001, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 1/0, Number.MIN_VALUE, 0, 42]); ");
/*fuzzSeed-209835301*/count=307; tryItOut("L:for(let a in ((function(y) { yield y; print(undefined);function (this.zzz.zzz)()\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return +((562949953421313.0));\n    (Uint8ArrayView[4096]) = ((((2.4178516392292583e+24) > (2147483647.0)) ? ((~~(+(1.0/0.0))) > (abs((((!(0xd1508625)))|0))|0)) : (i2))+(0x714eeff3));\n    i2 = (0x32f00706);\n    i3 = (0x52c3e0e1);\n    return +((-1.888946593147858e+22));\n  }\n  return f;this.i2 = new Iterator(i0, true);; yield y; })(+(4277).yoyo((y <<= x)))))g1.e0.delete(o2.f0);");
/*fuzzSeed-209835301*/count=308; tryItOut("d = (makeFinalizeObserver('nursery'));return /*UUV2*/(x.filter = x.getUint8);\ng1.v0 = a2.length;\n");
/*fuzzSeed-209835301*/count=309; tryItOut("((makeFinalizeObserver('nursery')));");
/*fuzzSeed-209835301*/count=310; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-209835301*/count=311; tryItOut("mathy2 = (function(x, y) { return Math.max(Math.min(( + ( + ( + (( + y) >> ( + Math.acosh(x)))))), (( + (0x07fffffff >>> 0)) >>> 0)), (( - mathy0(Math.pow(-0x07fffffff, Math.cosh(( + Math.fround(2**53-2)))), ( + (((y < ((x ** (y | 0)) | 0)) >>> 0) >>> 0)))) >>> 0)); }); testMathyFunction(mathy2, [0x080000001, -0x100000000, 0/0, 1.7976931348623157e308, -0x080000000, -0x100000001, -1/0, 0x0ffffffff, 2**53, -0x07fffffff, 0, 0.000000000000001, -(2**53), 1, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000000, -0, 2**53-2, 0x080000000, -(2**53-2), 0x07fffffff, -0x080000001, -Number.MAX_VALUE, 0x100000001, -(2**53+2), Math.PI, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 2**53+2, 1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=312; tryItOut("\"use strict\"; o1.t0.toSource = f1;");
/*fuzzSeed-209835301*/count=313; tryItOut("\"use strict\"; window;");
/*fuzzSeed-209835301*/count=314; tryItOut("\"use strict\"; print(uneval(i1));");
/*fuzzSeed-209835301*/count=315; tryItOut("let (b) { v1 = Object.prototype.isPrototypeOf.call(m1, o0); }");
/*fuzzSeed-209835301*/count=316; tryItOut("\"use strict\"; this.v1.__proto__ = f1;");
/*fuzzSeed-209835301*/count=317; tryItOut("\"use strict\"; t2 = new Uint32Array(b2);null;");
/*fuzzSeed-209835301*/count=318; tryItOut("\"use strict\"; switch(((/*wrap3*/(function(){ var phvztd =  '' ; (mathy1)(); }))().eval(\"print(x);\"))) { default: break; case 5: /*infloop*/ for (let window of x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor:  \"\" , getPropertyDescriptor:  /x/ , defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return true; }, get: function() { throw 3; }, set: function() { return true; }, iterate: undefined, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(true), function(y) { yield y; h0.fix = (function() { m0.get(v0); return g2.h0; });; yield y; }, (function(x, y) { return x; })).yoyo((eval(\"mathy5 = (function(x, y) { return Math.exp((((( ! Math.fround(mathy2(Math.fround(Math.sqrt(Math.fround((( + y) < (Math.imul((y | 0), (x | 0)) >>> 0))))), Math.fround(y)))) ? (( ! (( ! (((y > x) | 0) >>> 0)) >>> 0)) | 0) : (Math.hypot(((Math.max((y | 0), y) >>> 0) != (x >>> 0)), (Math.min((2**53+2 % Math.hypot(x, ( + x))), Math.fround(( ~ x))) | 0)) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy5, [-0x080000000, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, -0x0ffffffff, 2**53, 0x07fffffff, Math.PI, -(2**53), 1/0, -0x080000001, -0x100000001, 42, -(2**53+2), -0x07fffffff, 0x100000001, 1, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, 0, 2**53+2, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2]); \").__defineSetter__(\"x\", (({window: this})))))) {/*RXUB*/var r = /(?!\\2){1,}/yi; var s = \"\\uf956\\n\\uf956\\n_\\u0090\\n\\n\\n\\uf956\\n\\uf956\\n_\\n\\n\\u851e0\\n\\n\\u851e_\\n\\n\\u851e\\uf956\\n\\uf956\\n_\"; print(uneval(s.match(r))); h1.__proto__ = this.f1; }case 9: g1.t1 + '';break; case 4: this.zzz.zzz;break; break; print(a1); }");
/*fuzzSeed-209835301*/count=319; tryItOut("\"use asm\"; m2.has(f2);");
/*fuzzSeed-209835301*/count=320; tryItOut("a1.forEach((function(j) { if (j) { try { Object.defineProperty(this, \"o0.v2\", { configurable: (x % 4 == 3), enumerable: (x % 62 == 24),  get: function() {  return evaluate(\"\\\"use strict\\\"; mathy2 = (function(x, y) { return Math.min(( + Math.log(( + ( + ( + ( + -(2**53-2))))))), mathy0(( + ( + Math.hypot(( + Math.fround(Math.sinh(Math.fround(mathy1(y, x))))), ((Math.sqrt((x | 0)) | 0) >>> 0)))), (Math.sinh(Math.cosh(mathy1(( ! y), Math.asin(( + x))))) >>> 0))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), [0], (new Number(-0)), (function(){return 0;}), ({toString:function(){return '0';}}), (new Boolean(false)), '', (new Number(0)), [], '\\\\0', 0, /0/, NaN, 1, (new Boolean(true)), 0.1, ({valueOf:function(){return '0';}}), undefined, '/0/', false, '0', ({valueOf:function(){return 0;}}), (new String('')), -0, true, null]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: /(?!(?:\\3))?[^]/i, noScriptRval: false, sourceIsLazy: false, catchTermination: false })); } }); } catch(e0) { } try { o1.t2.valueOf = (function mcc_() { var xroxkl = 0; return function() { ++xroxkl; f2(true);};})(); } catch(e1) { } try { m1 + o2; } catch(e2) { } function f0(v0) \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(0x9f70073c)));\n  }\n  return f; } else { f0(v2); } }), this.g1, m0);return;");
/*fuzzSeed-209835301*/count=321; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.expm1((( + ( + ( + (Math.max((x | 0), (y | 0)) | 0)))) ? (( + ( ~ ( + y))) | 0) : Math.fround(Math.cbrt(((( ~ ((2**53+2 + -Number.MAX_SAFE_INTEGER) ** x)) >>> 0) >>> 0))))); }); testMathyFunction(mathy0, [1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, -(2**53-2), 42, -0, -0x100000000, -0x100000001, -0x080000001, -1/0, 0/0, -(2**53), -0x080000000, 0x080000001, 1/0, -0x0ffffffff, Number.MAX_VALUE, Math.PI, 0x080000000, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, 0x100000000, 2**53]); ");
/*fuzzSeed-209835301*/count=322; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-209835301*/count=323; tryItOut("m0.__iterator__ = (function() { a2.shift(g1, a0, p2, g1); return g1.t1; });");
/*fuzzSeed-209835301*/count=324; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, 0/0, 2**53-2, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, -0x100000001, 0x07fffffff, Number.MIN_VALUE, 2**53+2, -1/0, 0.000000000000001, -0x100000000, 0x100000001, Math.PI, -0x080000000, -0, 0x100000000, 0, 42, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 1/0, 0x080000000, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=325; tryItOut("\"use strict\"; M:switch(x) { default: case (4277): break; break; break;  }");
/*fuzzSeed-209835301*/count=326; tryItOut("mathy3 = (function(x, y) { return ( + ( - ( ! ( ! (Math.log2(mathy2(( + x), y)) >>> 0))))); }); testMathyFunction(mathy3, [/0/, (new Number(-0)), [0], 0, undefined, 0.1, objectEmulatingUndefined(), (function(){return 0;}), '\\0', -0, '', 1, [], ({valueOf:function(){return '0';}}), NaN, null, false, (new String('')), ({toString:function(){return '0';}}), '/0/', (new Boolean(true)), ({valueOf:function(){return 0;}}), (new Number(0)), '0', (new Boolean(false)), true]); ");
/*fuzzSeed-209835301*/count=327; tryItOut("a1.shift();");
/*fuzzSeed-209835301*/count=328; tryItOut("\"use strict\"; /*infloop*/for(let y; /(?=(?!.((?!.))|.)).(\\uD0D5*?)/gi; /*FARR*/[new RegExp(\"(?!(\\\\d$+)(?=^[^]\\\\1)|[^]|\\\\u00Cd\\\\w|.?)\", \"ym\")].filter(y => Object.defineProperty(set, \"a\", ({get: Math.atan2(15, (x = new RegExp(\"(?=(\\u35db\\\\B|\\\\S|\\\\2|\\\\u0062))?|.\", \"yim\")))})))) {print(uneval(o1.t2));Object.prototype.unwatch.call(p1, \"wrappedJSObject\"); }");
/*fuzzSeed-209835301*/count=329; tryItOut("\"use strict\"; e0.add(o2);");
/*fuzzSeed-209835301*/count=330; tryItOut("o0 = {};");
/*fuzzSeed-209835301*/count=331; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + ((Math.sinh(x) < x) === ( + (( ~ (y | 0)) | 0)))) | 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0.000000000000001, 0x100000001, 0/0, 1.7976931348623157e308, 0x0ffffffff, 42, 1/0, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, Number.MAX_VALUE, -(2**53-2), 0x080000001, 2**53+2, -0x080000001, -0x100000000, 2**53, Number.MIN_VALUE, -1/0, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2, -(2**53), 0x100000000, -Number.MAX_VALUE, 0x080000000, 0, 1]); ");
/*fuzzSeed-209835301*/count=332; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.max((Math.fround((( + ( ~ ( + mathy1(Math.min(mathy0((( - y) >>> 0), Math.fround(Math.pow(Math.fround(-0x0ffffffff), y))), x), x)))) >>> 0)) >>> 0), (((( - ( + Math.tan(Math.log10(x)))) >>> 0) ? (Math.fround(( - Math.fround(Math.fround(( + ( + y)))))) >>> 0) : (( + mathy0(( + 0x080000000), ( + ( + ( ! ( + ((((x << y) | 0) << (Math.fround(Math.cosh(Math.fround(Math.fround(Math.imul(( + -0x100000001), Math.fround(0x100000000)))))) | 0)) | 0))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [2**53, -Number.MIN_VALUE, Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0, -Number.MAX_VALUE, 0x100000000, -0x100000001, Number.MAX_VALUE, -0x080000000, 1, 0/0, -(2**53+2), Math.PI, 0x100000001, -0x0ffffffff, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), -0, 2**53-2, 0.000000000000001, -1/0, 42, -0x080000001, 0x080000000, 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=333; tryItOut("var a = ( /x/ .yoyo(([])));p1 + e1;");
/*fuzzSeed-209835301*/count=334; tryItOut("\"use strict\"; (--SharedArrayBuffer);");
/*fuzzSeed-209835301*/count=335; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3*\", \"yi\"); var s = x; print(uneval(r.exec(s))); let y =  /x/ ;");
/*fuzzSeed-209835301*/count=336; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.imul(Math.fround(Math.atanh((Math.ceil(y) >>> 0))), (((-Number.MAX_SAFE_INTEGER || Math.fround(y)) | 0) * (((( ~ y) <= 2**53) === Math.max(y, x)) | 0)))); }); testMathyFunction(mathy5, [-0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, Math.PI, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -0x100000000, -0x0ffffffff, 0.000000000000001, 0, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -(2**53-2), 0x080000001, 0x080000000, -0x080000001, 1/0, 0x100000001, 2**53-2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000001, 42, -(2**53), 2**53+2]); ");
/*fuzzSeed-209835301*/count=337; tryItOut("/*vLoop*/for (var srtemu = 0; srtemu < 18; ++srtemu) { const z = srtemu; print(v2); } ");
/*fuzzSeed-209835301*/count=338; tryItOut("v1 = a1.length;");
/*fuzzSeed-209835301*/count=339; tryItOut("mathy0 = (function(x, y) { return Math.log((Math.imul((((Math.log10(y) | 0) & (Math.imul(Math.sin(Math.pow(x, y)), ((((Math.max((x >>> 0), (y >>> 0)) >>> 0) | 0) % (2**53-2 | 0)) | 0)) | 0)) | 0), ((Math.fround((x | 0)) | 0) | 0)) >>> 0)); }); testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, Math.PI, -0x0ffffffff, 0x080000001, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -(2**53-2), -0x100000001, 0x100000000, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, 2**53-2, Number.MAX_VALUE, 0/0, 42, 2**53, -1/0, 1.7976931348623157e308, 0.000000000000001, -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), -0, -0x07fffffff, Number.MIN_VALUE, -0x080000001, 2**53+2, 0]); ");
/*fuzzSeed-209835301*/count=340; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -8388607.0;\n    i0 = (0xf8cab39a);\n    {\n      {\n        {\n          (Float64ArrayView[(((0x71aaccba))) >> 3]) = ((d1));\n        }\n      }\n    }\n    (Uint16ArrayView[0]) = (((0xff0ae35a) ? ((-7.555786372591432e+22) <= (+(((0xfe50325a)-(0x965d0ab9)) & ((0xfe4a2c5e))))) : (0xf8b2d2a3))-(!(!((-1.5111572745182865e+23) < (d2)))));\n    d1 = (+((NaN)));\n    return (((((((0xfffff*(i0))>>>(((-3.777893186295716e+22) < (-4503599627370497.0))-(-0x8000000))) / (0x4b4a242f))>>>((0x30f131fb)-(i0)+(-0x8000000))))+((((((0x2a923569)-(0xfd7c5fe9)+(0x4a2a57b5))>>>((i0)*-0x6d1ef)) / (0x0)) << ((i0))))))|0;\n  }\n  return f; })(this, {ff: (x =  /x/ ).bind((4277))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=341; tryItOut("h2.getOwnPropertyNames = (function() { try { g0.v0 = t0.length; } catch(e0) { } try { v0 = this.g0.r1.toString; } catch(e1) { } v2 = new Number(NaN); return e2; });");
/*fuzzSeed-209835301*/count=342; tryItOut("\"use strict\"; delete v2[\"create\"];");
/*fuzzSeed-209835301*/count=343; tryItOut("\"use strict\"; i1 = new Iterator(t2);");
/*fuzzSeed-209835301*/count=344; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.imul(Math.pow(((mathy3(Number.MIN_SAFE_INTEGER, x) || (( - (x >>> 0)) | 0)) >>> (( ! ( - Math.trunc(( + (( ! x) >>> 0))))) >>> 0)), (Math.hypot((x ? x : Math.acos(mathy1(Math.fround(x), Math.fround(Number.MAX_VALUE)))), Math.fround(Math.ceil(Math.fround((Math.ceil((2**53+2 | 0)) | 0))))) >>> 0)), Math.fround(Math.sinh(Math.fround(Math.abs(( + Math.pow(( + (x ^ x)), x))))))); }); testMathyFunction(mathy4, /*MARR*/[{}, new Boolean(true), (-1/0), {}, new Boolean(true), (-1/0), new Boolean(true), {}, (-1/0), {}, {}, new String('q'), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (-1/0), {}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (-1/0), (-1/0), (-1/0), (-1/0), new String('q'), {}, {}, {}, new String('q'), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, (-1/0), {}, new Boolean(true), {}, new String('q'), new String('q'), new Boolean(true), {}, new Boolean(true), new String('q'), (-1/0), new String('q'), (-1/0)]); ");
/*fuzzSeed-209835301*/count=345; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=346; tryItOut("mathy2 = (function(x, y) { return ( - mathy1((( ! y) >>> 0), (Math.atan2((Math.cbrt(y) >>> 0), -0x080000000) >>> 0))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -0x0ffffffff, -0x080000001, Number.MIN_VALUE, 2**53, 0x100000001, 0.000000000000001, -0x080000000, -0x07fffffff, -Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -0, 1, -(2**53), 0/0, 0x07fffffff, -(2**53+2), Math.PI, 1/0, -0x100000000, 42, -(2**53-2), 2**53-2, 0x080000000, 0x080000001]); ");
/*fuzzSeed-209835301*/count=347; tryItOut("mathy5 = (function(x, y) { return (( + ( ~ Math.fround((( + ( ! (Math.clz32((x | 0)) | 0))) < ( + ( + Math.fround(( + mathy0(x, Math.fround(y)))))))))) , Math.log10(Math.atan(Math.atan2(y, 2**53)))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -(2**53), -0x100000000, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 1/0, 1, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001, 2**53+2, 2**53, 0x100000000, -0x080000001, 0x07fffffff, -0x0ffffffff, 0, 0x080000000, Number.MAX_VALUE, -(2**53-2), -0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 0x080000001, -Number.MAX_VALUE, 0.000000000000001, -1/0, -(2**53+2), 42, 0/0]); ");
/*fuzzSeed-209835301*/count=348; tryItOut(";");
/*fuzzSeed-209835301*/count=349; tryItOut("v2 = Object.prototype.isPrototypeOf.call(e2, p0);");
/*fuzzSeed-209835301*/count=350; tryItOut("/*RXUB*/var r = /(?:.*|(\\b)[^\\v-\\u8050)-`]?|^?|(.)*)|[^]|((?=\\b|[^]+?)|(?:[^])\\3)\\cG|^$.{4,6}[^\\S]|\\\uf913*{0}(?=((?=.))(\u00f0|.)|[^]+?){2,}*?/gyim; var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=351; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"L:if(( ''  || \\\"\\\\uDCA1\\\")) { if (false) print(/*UUV2*/(x.getUTCDay = x.prototype));} else {a0.length = 19;Array.prototype.sort.call(a1, (function mcc_() { var spalde = 0; return function() { ++spalde; if (spalde > 1) { dumpln('hit!'); try { g1.i2.next(); } catch(e0) { } /*RXUB*/var r = r2; var s = \\\"\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\\u4b7b\\\\nz\\\\n\\\\n\\\\n\\\\n\\\"; print(s.match(r)); print(r.lastIndex);  } else { dumpln('miss!'); try { g0.offThreadCompileScript(\\\"/* no regression tests found */\\\"); } catch(e0) { } try { f1 = this.m2.get(t1); } catch(e1) { } a1 = new Array; } };})(), s2, e1, o2, e2, b0, f2); }\");");
/*fuzzSeed-209835301*/count=352; tryItOut("\"use strict\"; a2[0] = e2;");
/*fuzzSeed-209835301*/count=353; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return ( + (Math.acosh((Math.log2(((((y >>> 0) % y) >>> 0) % y)) >>> 0)) * ( + Math.max(Math.imul(x, Math.min(-0, (( + (x >>> Number.MIN_VALUE)) && ( + x)))), y)))); }); testMathyFunction(mathy0, [-(2**53+2), -1/0, 1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, -0, 1, 0x07fffffff, Math.PI, -Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, -0x07fffffff, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 42, 0x100000001, -0x080000001, 0x080000001, -(2**53), 2**53, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=354; tryItOut("print(uneval(a0));");
/*fuzzSeed-209835301*/count=355; tryItOut("((void options('strict_mode')));\n/* no regression tests found */\n");
/*fuzzSeed-209835301*/count=356; tryItOut("p2 + s1;\n\u0009/* no regression tests found */\n");
/*fuzzSeed-209835301*/count=357; tryItOut("v0 = t2.length;");
/*fuzzSeed-209835301*/count=358; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.hypot((Math.log10(((Math.exp((Math.min(y, (( ! y) >>> 0)) | 0)) | 0) > (( ! y) | 0))) | 0), ( + Math.log((( + (( + Math.clz32(y)) >> ( + y))) | 0)))); }); testMathyFunction(mathy1, [-(2**53), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, 1, 0x100000001, -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 0, -(2**53-2), -0x100000000, 2**53+2, Number.MAX_VALUE, 2**53-2, 42, -0x07fffffff, 1/0, 0x07fffffff, Number.MIN_VALUE, -0, 0/0, 0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -1/0, 0x080000001]); ");
/*fuzzSeed-209835301*/count=359; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min((Math.abs(((y != (Number.MAX_SAFE_INTEGER >> ( ! Math.fround(x)))) | 0)) | 0), mathy0(Math.exp(Math.fround((Math.fround(x) & Math.fround(Math.imul(Math.fround(Math.hypot((y | 0), Math.fround(x))), (x >>> 0)))))), ( + (( - Math.log(Math.cos(1/0))) | 0)))); }); testMathyFunction(mathy1, [-(2**53-2), Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, 1, -0, 0x0ffffffff, 1/0, -Number.MAX_VALUE, 0/0, 0, -1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, -0x080000000, -0x07fffffff, -0x100000001, 1.7976931348623157e308, 0x07fffffff, -(2**53), 42, -Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, 0x100000001]); ");
/*fuzzSeed-209835301*/count=360; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 1, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, -0x100000000, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, -0x100000001, 0x080000001, 42, 1.7976931348623157e308, 0/0, -0x07fffffff, 0x080000000, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, -0, -0x080000000, 0, 2**53+2, 0x100000001, 1/0, -(2**53+2), 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -1/0]); ");
/*fuzzSeed-209835301*/count=361; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.round(Math.sin((Math.pow(Math.clz32(x), ((y << ( + ( + -0x07fffffff))) | 0)) >>> 0))) | 0); }); ");
/*fuzzSeed-209835301*/count=362; tryItOut("\"use strict\"; this.a0 = [(4277) if (x instanceof  /x/g )];");
/*fuzzSeed-209835301*/count=363; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( + Math.cos(((( ! ((((-Number.MAX_VALUE ? x : (( + ( + x)) | 0)) ? Math.fround(( ~ y)) : (((y / x) << y) | 0)) | 0) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy4, [-(2**53-2), 1, 2**53-2, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0/0, 2**53, -0x100000001, -1/0, 42, 0x100000000, Math.PI, 0x080000001, 1/0, 1.7976931348623157e308, 2**53+2, 0, -0x080000001, -(2**53+2), 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, 0x080000000, -0x100000000, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-209835301*/count=364; tryItOut("v2 = new Number(NaN);");
/*fuzzSeed-209835301*/count=365; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[NaN, NaN, new Number(1), new Number(1), NaN, new Number(1), NaN, new Number(1), new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), NaN, new Number(1), NaN, new Number(1), new Number(1), new Number(1), NaN, NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), new Number(1), NaN, NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), NaN, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), NaN, NaN, NaN, NaN, NaN, new Number(1), new Number(1), NaN, new Number(1), new Number(1), new Number(1), new Number(1), NaN, NaN, NaN, NaN, NaN, NaN, new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), NaN, NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1)]) { let(b) { for (var p in p0) { t2 = t2.subarray(NaN, 13); }} }");
/*fuzzSeed-209835301*/count=366; tryItOut("a2 = neuter;");
/*fuzzSeed-209835301*/count=367; tryItOut("this.g1.o1.e0.has((({a1:1}) for (x of (function() { \"use strict\"; yield  \"\" ; } })()) for each (x in []) for ((c) in \"\\u0990\") for each (x in [])));");
/*fuzzSeed-209835301*/count=368; tryItOut("print(x);\nprint(o1.e2);\n");
/*fuzzSeed-209835301*/count=369; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(g0, \"1\", { configurable: false, enumerable: (x % 3 != 2), get: f1, set: WeakSet.bind(o2.i0) });");
/*fuzzSeed-209835301*/count=370; tryItOut("\"use strict\"; switch((eval = y = -21)) { default: Array.prototype.unshift.call(a2, g2.e0, g1.h1, v1, h0);case x: Array.prototype.pop.call(a0); }");
/*fuzzSeed-209835301*/count=371; tryItOut("\"use strict\"; /*bLoop*/for (var wiynnx = 0; wiynnx < 3; ++wiynnx) { if (wiynnx % 3 == 2) { /*hhh*/function zqgjpc(x, window){s2 += 'x';}zqgjpc(null, \"\\uD738\"); } else { h1[\"setUint32\"] = e0;\ne2.add(g2.o2);\n }  } ");
/*fuzzSeed-209835301*/count=372; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - Math.fround(Math.asinh(Math.fround((Math.max((Math.max(y, ( + mathy1(( + Math.log1p(y)), ((x ? ( ! -(2**53+2)) : x) >>> 0)))) >>> 0), (((2**53-2 >>> 0) ? (( - Math.fround(Number.MIN_SAFE_INTEGER)) >>> 0) : (( + x) >>> 0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [0, -0x0ffffffff, -(2**53+2), 1/0, -(2**53), Number.MIN_VALUE, 0x0ffffffff, -0x100000000, -0, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 0/0, 0x100000000, 2**53, Math.PI, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, -0x080000000, -Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0x080000000, 2**53+2, 0x100000001, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=373; tryItOut("a2.reverse(m0, f0, o1, (Date.UTC).apply((4277), c = null));");
/*fuzzSeed-209835301*/count=374; tryItOut("\"use strict\"; m0.has(g2);");
/*fuzzSeed-209835301*/count=375; tryItOut("L:if(true) t2 = new Int16Array(v0); else  if ((-- /x/g .__proto__ &= new RegExp(\"(?!(?=$)+?)\", \"im\"))) /* no regression tests found */");
/*fuzzSeed-209835301*/count=376; tryItOut("/*RXUB*/var r = /(?!(?:\\3))/m; var s = \"\\u1d37\\n\\n\"; print(s.replace(r, new RegExp(\"(?:(?:\\\\s*|\\\\b)|[^]|\\\\v|\\\\d*?+?(?!^))\", \"gym\"))); ");
/*fuzzSeed-209835301*/count=377; tryItOut("o2.f0 + o1.s0;");
/*fuzzSeed-209835301*/count=378; tryItOut("mathy5 = (function(x, y) { return Math.max((( ~ (((mathy0((Math.fround(( ~ Math.fround(x))) | 0), (Math.imul(x, Math.imul(-0x100000001, x)) | 0)) | 0) | 0) + (( + x) | 0))) >>> 0), ( - ( ! Math.fround((Math.log10(x) ? x : Number.MIN_VALUE))))); }); testMathyFunction(mathy5, [/0/, (new Boolean(true)), NaN, '', 0, '\\0', (new Number(-0)), '/0/', true, objectEmulatingUndefined(), undefined, 0.1, false, '0', (new Boolean(false)), [0], 1, -0, (new String('')), ({toString:function(){return '0';}}), (new Number(0)), [], ({valueOf:function(){return '0';}}), null, ({valueOf:function(){return 0;}}), (function(){return 0;})]); ");
/*fuzzSeed-209835301*/count=379; tryItOut("e1.__iterator__ = (function mcc_() { var saexnw = 0; return function() { ++saexnw; if (/*ICCD*/saexnw % 9 == 6) { dumpln('hit!'); try { v0 = true; } catch(e0) { } a2 = r0.exec(s0); } else { dumpln('miss!'); try { for (var v of m1) { try { print( /x/ ); } catch(e0) { } try { a1.push(); } catch(e1) { } try { /*MXX1*/o1 = g1.RegExp.prototype.test; } catch(e2) { } g2.offThreadCompileScript(\"o2 = Object.create(o2);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: \"\\u6B01\", noScriptRval: 7, sourceIsLazy: true, catchTermination: (x % 8 != 7), sourceMapURL: o1.s1 })); } } catch(e0) { } v2 = (m0 instanceof g1.a1); } };})()\ns2 = '';");
/*fuzzSeed-209835301*/count=380; tryItOut("/*RXUB*/var r = /[^\\Q-\\\u7f56\\u003B-{\\u7173]|(((?![\\cB\\S]))*?)[^]|(?:.)\\w*/yim; var s = \"\\n_000a00\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=381; tryItOut("try { let(x) ((function(){return;})()); } catch(d if (function(){const x, dhkslh;for (var v of o0) { g0 = this; }w =  /* Comment */(4277);})()) { return ({x: allocationMarker() }); } catch(y if (function(){/*RXUB*/var r = /.^{1}|(?=(\\w|\\b+?))?|[^]|(?:[\\w\\ua35a\\S\\0]|\\v[^]|.){4,5}[\u3a55\\W\\u003c\u00a3]+?|((\\B*){3,4})+(?!^)[^]/yim; var s = \"\\u00ca\"; print(r.test(s)); })()) { return window; } ");
/*fuzzSeed-209835301*/count=382; tryItOut("e0 + h0;");
/*fuzzSeed-209835301*/count=383; tryItOut("/*MXX1*/o1 = this.g0.Set.prototype.forEach;");
/*fuzzSeed-209835301*/count=384; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x080000000, Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, 0, -1/0, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, -(2**53+2), -0x080000001, -(2**53-2), 0x0ffffffff, 2**53-2, 0x100000000, Math.PI, 2**53, -(2**53), 0x100000001, Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 2**53+2, -0x100000001, 42, 0x080000001, Number.MAX_VALUE, 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-209835301*/count=385; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow(Math.trunc((mathy2(((((Math.atan2(x, (Math.min(( + Math.exp(( + y))), ((Math.min((x >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0) ^ (Math.pow(y, y) >>> 0)) >>> 0) | 0), (Math.atan2(0/0, ( - 2**53)) | 0)) >>> 0)), (mathy3(( + y), ( + (y < x))) ? (Math.acosh(Math.asin(x)) | 0) : (Math.imul((Number.MAX_SAFE_INTEGER >>> 0), y) & mathy0((Math.round(x) * Math.fround((x >= y))), ((x >> Math.fround(Math.exp(Math.fround(2**53)))) | 0))))); }); ");
/*fuzzSeed-209835301*/count=386; tryItOut("Array.prototype.forEach.apply(a1, [(function() { for (var j=0;j<90;++j) { f2(j%2==1); } })]);");
/*fuzzSeed-209835301*/count=387; tryItOut("\"use strict\"; for(let y in ((function () { yield delete x.x } )((x >> \"\\u4664\"))))t1[new RegExp(\"(\\\\b)\", \"gyim\")];");
/*fuzzSeed-209835301*/count=388; tryItOut("v0 = evalcx(\"this.v2 = t2.byteLength;\", this.g2);");
/*fuzzSeed-209835301*/count=389; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan2(( - mathy0(y, y)), Math.min(Math.fround((( + mathy1(( + ( ~ ( + Math.fround(( ~ Math.fround(y)))))), (( ~ (Math.cos(x) | 0)) | 0))) >> ( + (Math.fround(( + Math.fround(y))) >>> Math.max(mathy1(y, x), ( + Math.min(( + 42), ( + y)))))))), (((( ! Math.pow(((y ? -Number.MIN_VALUE : Math.imul(x, (x >>> 0))) >>> 0), ( + x))) | 0) & (Math.exp((Math.sign(Math.log1p((y | 0))) >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -(2**53), 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, -Number.MIN_VALUE, 2**53, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0, -(2**53+2), -1/0, Number.MAX_VALUE, 0.000000000000001, 0x080000000, -0x100000001, 0x080000001, 0x100000001, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53-2), 0x100000000, -0x080000001, 1, -0x080000000, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=390; tryItOut("/*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { e1.add(let (d) Math.expm1(-1914470153));return 15; }}), { configurable: true, enumerable: (x % 3 != 2), get: f1, set: (function() { try { v0 = Object.prototype.isPrototypeOf.call(this.s2, g2.o0); } catch(e0) { } g0.a0.sort((function(j) { if (j) { try { h2.toString = (function() { for (var j=0;j<11;++j) { f1(j%5==1); } }); } catch(e0) { } try { a1[x <= y] = (4277); } catch(e1) { } Object.seal(s1); } else { try { v0[\"__proto__\"] = s1; } catch(e0) { } try { v2 = evalcx(\"v2 = r0.unicode;\", o1.g1); } catch(e1) { } try { print(m2); } catch(e2) { } i0.valueOf = (function mcc_() { var lkzkgp = 0; return function() { ++lkzkgp; if (/*ICCD*/lkzkgp % 9 == 8) { dumpln('hit!'); for (var p in m1) { try { m0.has(v2); } catch(e0) { } try { this.g2.m1.has(v0); } catch(e1) { } print(this.h0); } } else { dumpln('miss!'); try { this.v0 = Object.prototype.isPrototypeOf.call(b2, o2.f1); } catch(e0) { } ; } };})(); } }), m2, b0); return g1.o2.t0; }) });");
/*fuzzSeed-209835301*/count=391; tryItOut("\"use strict\"; {a0 = r2.exec(this.s0);a0.unshift(); }");
/*fuzzSeed-209835301*/count=392; tryItOut("\"use strict\"; /*infloop*/ for  each(let eval in Math.pow(\"\\uDABD\", /\\b/g)) print(x);");
/*fuzzSeed-209835301*/count=393; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.max(((Math.fround((((Math.acosh(Math.exp(x)) | 0) && ((Math.atan2(( + mathy1(x, ( ~ ( + Math.abs(( + y)))))), Math.sqrt(( ! y))) >>> 0) | 0)) | 0)) < (( + Math.exp(y)) | y)) | 0), Math.fround((Math.tanh((Math.exp(Math.fround(y)) | 0)) == Math.fround(Math.fround(Math.atan2((Math.log1p(x) | 0), (Math.abs(( + (x >>> 0))) | 0))))))); }); testMathyFunction(mathy3, [Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, -0x080000001, -0x080000000, -0x100000000, -Number.MAX_VALUE, 0x100000000, -(2**53), 0x100000001, 0x080000000, -1/0, -0, 2**53+2, -(2**53-2), 0, Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 42, 1/0, Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, 1, 0.000000000000001, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-209835301*/count=394; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"L: {m0 = new WeakMap; }\");");
/*fuzzSeed-209835301*/count=395; tryItOut("s0 += 'x';");
/*fuzzSeed-209835301*/count=396; tryItOut("a2[16] = new ((window%=(eval(\"mathy4 = (function(x, y) { return Math.asin(( + Math.fround(Math.sqrt((y || y))))); }); testMathyFunction(mathy4, [0, undefined, '0', false, (new String('')), true, objectEmulatingUndefined(), '/0/', (new Boolean(false)), /0/, [], ({valueOf:function(){return 0;}}), NaN, -0, [0], (function(){return 0;}), (new Boolean(true)), '\\\\0', ({toString:function(){return '0';}}), (new Number(0)), (new Number(-0)), null, ({valueOf:function(){return '0';}}), '', 1, 0.1]); \") instanceof true)))();");
/*fuzzSeed-209835301*/count=397; tryItOut("\"use strict\"; g0 + '';/*iii*/v1 = Object.prototype.isPrototypeOf.call(a0, this.o0.m1);/*hhh*/function ippjpm(\u3056 = x, c = -20 &= window, x, x = ({a1:1}), z, NaN, x =  /x/g , w, w, NaN, e, x, x, x, NaN, window = -0, c =  /x/g , b, x = e, e, \u3056, window, b, eval, NaN, \u3056 = this, eval, \u3056, x, z =  '' , b, a, e, x, x =  '' , d, window, z = true, x, d, window, z, x, z, x, window, b, NaN){break ;}while((((a) = (window.throw( '' )))) && 0){window;( /x/ ); }");
/*fuzzSeed-209835301*/count=398; tryItOut("x = \u3056;");
/*fuzzSeed-209835301*/count=399; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.min(Math.fround(Math.fround(Math.tan(((Math.fround(Math.hypot(2**53-2, x)) >>> 0) | 0)))), Math.fround(Math.fround(Math.exp(Math.fround((y | x))))))) >= (( - 1) | (mathy2(Math.acosh(2**53+2), (Math.max((((( + ( + -Number.MAX_VALUE)) >>> 0) , (x >>> 0)) >>> 0), ((-1/0 , (( + Math.fround(x)) >>> 0)) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy3, [-0, 1/0, -Number.MAX_VALUE, 0x100000000, -0x07fffffff, 2**53, -Number.MIN_VALUE, Number.MAX_VALUE, -1/0, 0x0ffffffff, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, Math.PI, 1.7976931348623157e308, -0x080000000, 0.000000000000001, -0x100000000, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 0x080000001, 42, -(2**53+2), -(2**53), 0, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=400; tryItOut("\"use strict\"; for (var p in this.h2) { g0.t2 = t1.subarray(18, 15); }");
/*fuzzSeed-209835301*/count=401; tryItOut("testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), NaN, objectEmulatingUndefined(), undefined, (new Number(-0)), (new Boolean(false)), '/0/', [0], (new Boolean(true)), /0/, null, (new Number(0)), 0, ({toString:function(){return '0';}}), '\\0', '', [], true, -0, 1, 0.1, (function(){return 0;}), (new String('')), '0', false, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-209835301*/count=402; tryItOut("/*infloop*/for(let arguments.callee.caller.arguments in (( '' )(({b:  \"\" }))))(this);");
/*fuzzSeed-209835301*/count=403; tryItOut("\"use strict\"; m1.set(Math.max(-6, -17), m2);");
/*fuzzSeed-209835301*/count=404; tryItOut("\"use strict\"; /*vLoop*/for (var gzivav = 0; gzivav < 36; ++gzivav) { w = gzivav; this.startsWith } ");
/*fuzzSeed-209835301*/count=405; tryItOut("throw x;function x(c, d)[z1,,]b0 + this.g2;\n(\n/\\1\\S*+?|\\S|\\b+|\u00c1{1,}{1,5}(?=(\\w))(?!^|[^]+\\2?)|\\1/gm);\n");
/*fuzzSeed-209835301*/count=406; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((4277));\n    i0 = ((0xc82e884f));\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: Set.prototype.add}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0, -0x100000001, 0, 0x100000001, -0x100000000, 0x080000000, 2**53-2, -0x080000000, 1, 1.7976931348623157e308, 2**53, 1/0, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, 42, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, -1/0, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 0x100000000, 0.000000000000001, 2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=407; tryItOut("o2.v2 = Object.prototype.isPrototypeOf.call(i1, g0.s1);");
/*fuzzSeed-209835301*/count=408; tryItOut("g1.offThreadCompileScript(\"e1.add(h0);\");");
/*fuzzSeed-209835301*/count=409; tryItOut("{ void 0; void gc(); }");
/*fuzzSeed-209835301*/count=410; tryItOut("mathy2 = (function(x, y) { return (Math.trunc(Math.tanh(mathy1(Math.min((x >>> 0), Math.sin(y)), (((y >>> 0) >> (Math.max(((( + y) || Math.log10(0x080000000)) >>> 0), Number.MAX_VALUE) | 0)) >>> 0)))) | 0); }); testMathyFunction(mathy2, [0x0ffffffff, -0x080000000, -0x100000001, 0x100000000, -0, 42, Number.MAX_SAFE_INTEGER, -(2**53), 1, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -(2**53+2), 2**53+2, 0x07fffffff, 0.000000000000001, Math.PI, 0/0, -1/0, Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, -0x07fffffff, 0x080000001, Number.MAX_VALUE, 0x080000000, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=411; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.sqrt(Math.atanh(y))) | 0) < (Math.atan2(( - Math.fround(Math.atanh(x))), ( ~ x)) | 0)) | 0); }); testMathyFunction(mathy3, [0x07fffffff, 1/0, -0, 0x080000001, 1.7976931348623157e308, 0x100000000, 0x0ffffffff, Math.PI, -0x100000000, -0x080000000, Number.MAX_VALUE, 1, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, 0, 0x080000000, -(2**53), -(2**53+2), 0.000000000000001, -0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, 42, -1/0]); ");
/*fuzzSeed-209835301*/count=412; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return Math.fround((Math.fround(Math.atanh(( ! ( + ( ~ x))))) % Math.fround(mathy1(Math.fround((Math.max((Number.MAX_SAFE_INTEGER >>> 0), (0x100000001 >>> 0)) >>> 0)), Math.max(-0x07fffffff, Math.cosh(mathy1(x, y))))))); }); testMathyFunction(mathy3, [-(2**53+2), -0, 0.000000000000001, 42, 0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -(2**53), 2**53, 2**53+2, 1, Number.MIN_VALUE, 2**53-2, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -0x100000000, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -Number.MIN_VALUE, -0x100000001, 1/0]); ");
/*fuzzSeed-209835301*/count=413; tryItOut("m1 + this.b2;");
/*fuzzSeed-209835301*/count=414; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=415; tryItOut("/*RXUB*/var r = /[^]/; var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-209835301*/count=416; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=417; tryItOut("m0.has(b1);");
/*fuzzSeed-209835301*/count=418; tryItOut("/*infloop*/L:do (new RegExp(\"(\\\\B)|(?!\\\\u00B4)\", \"gy\")); while((4277));");
/*fuzzSeed-209835301*/count=419; tryItOut("\"use strict\"; var uuofcq = new SharedArrayBuffer(2); var uuofcq_0 = new Uint8ClampedArray(uuofcq); uuofcq_0[0] = 23; var uuofcq_1 = new Uint16Array(uuofcq); uuofcq_1[0] = 4288763291; var uuofcq_2 = new Uint32Array(uuofcq); print(uuofcq_2[0]); uuofcq_2[0] = -29; a0[15];this.m2.get(o0.s0);");
/*fuzzSeed-209835301*/count=420; tryItOut("\"use strict\"; if(undefined) Object.defineProperty(this, \"this.g0.o2\", { configurable: (x % 32 != 2), enumerable: (x % 56 != 15),  get: function() {  return Object.create(s0); } }); else  if ((new ( /x/g  ? true : -16)())) {(true); } else /*ODP-3*/Object.defineProperty(g1.s0, \"toSource\", { configurable: false, enumerable: true, writable: true, value: h1 });");
/*fuzzSeed-209835301*/count=421; tryItOut("\"use asm\"; /*MXX1*/var o2 = g1.Symbol.keyFor;");
/*fuzzSeed-209835301*/count=422; tryItOut("\"use strict\"; v0.__proto__ = f2;print(Math.pow(-0, x));");
/*fuzzSeed-209835301*/count=423; tryItOut("mathy2 = (function(x, y) { return ((Math.fround((((( - Math.atan2(x, (( - (y | 0)) | 0))) || (Math.fround((((mathy0((0x07fffffff >>> 0), 0x100000001) >>> 0) , x) >>> 0)) | 0)) << (((( ~ 2**53+2) | 0) ** (Math.sign(y) | 0)) | 0)) | 0)) ^ ( ! Math.pow(((( - ((( - (x >>> 0)) >>> 0) | 0)) | 0) >>> 0), x))) | 0); }); testMathyFunction(mathy2, [0, '\\0', (new Boolean(false)), '', (new Number(-0)), (function(){return 0;}), NaN, ({toString:function(){return '0';}}), false, [0], -0, 0.1, [], (new Boolean(true)), 1, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '0', null, (new String('')), (new Number(0)), true, '/0/', ({valueOf:function(){return 0;}}), /0/, undefined]); ");
/*fuzzSeed-209835301*/count=424; tryItOut("this.o1 + '';");
/*fuzzSeed-209835301*/count=425; tryItOut("i2.next();");
/*fuzzSeed-209835301*/count=426; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?:(\\W(?:\\3){3,})){3,})\\u425B(?:(?:[\\x2a-\u00ab\u00d1\\S]\\b?){0,})(?!.[^]|[^]{2,})\\1*|\\d+?/gm; var s = \"\\u0014\\n\\na a\\n \\u3e58\\n\\n\\u425b\\u425b\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=427; tryItOut("a0[this.v1] = (x.yoyo(x));(allocationMarker());");
/*fuzzSeed-209835301*/count=428; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.exp(( + ( + ( + Math.fround(( ! Math.fround(( - x)))))))); }); testMathyFunction(mathy1, /*MARR*/[({ set 13(x) { yield \"\\u9E53\" } , \"-14\":  /* Comment */x }), new String('')]); ");
/*fuzzSeed-209835301*/count=429; tryItOut("mathy3 = (function(x, y) { return (((((( - (Math.fround(Math.exp((( + ( ~ -Number.MIN_VALUE)) | 0))) | 0)) >>> 0) == mathy2(( + (y & Math.fround(Math.cbrt(Math.fround(x))))), ( + ( ! y)))) | 0) > Math.fround(mathy1(Math.fround(( ! Math.fround(( + Math.fround(Number.MAX_SAFE_INTEGER))))), Math.fround(( + (Math.cosh(x) & ( + (Number.MAX_SAFE_INTEGER * ( + mathy1(Number.MIN_SAFE_INTEGER, (x | 0))))))))))) | 0); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -0x080000001, -0x07fffffff, 0.000000000000001, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -0x100000001, 42, 0x080000000, -0, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 2**53-2, -(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -(2**53+2), 0x07fffffff, 0, 1.7976931348623157e308, -0x080000000, -0x100000000, 2**53, -1/0]); ");
/*fuzzSeed-209835301*/count=430; tryItOut("\"use strict\"; /*infloop*/M:for([, [, , , this.x, , ], , c, , {c: {b: c}, x: [y, , , ], c: {x, eval}, x, x: [, x, , , c], window: {length, w: [b, []], x: [], eval, this.window: {}, x: [{y: [], window: [, , , ], e: ReferenceError, z}, y], x, \u3056: []}, x: x, d, w}, , x, {x: [x, [, , , {}], , this], window: d}] = x instanceof this.__defineSetter__(\"x\", encodeURIComponent); ((function factorial(epmizm) { continue ;Int8Array; if (epmizm == 0) { ; return 1; } ; return epmizm * factorial(epmizm - 1);  })(0)).unwatch(\"defineProperties\"); (new function(q) { return q; }())) /*oLoop*/for (mmuepe = 0; mmuepe < 9; ++mmuepe) { yield window; } ");
/*fuzzSeed-209835301*/count=431; tryItOut("\"use strict\"; throw x;");
/*fuzzSeed-209835301*/count=432; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=433; tryItOut("print(uneval(e0));");
/*fuzzSeed-209835301*/count=434; tryItOut("/*RXUB*/var r = /(?:\\1*?)/y; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-209835301*/count=435; tryItOut("L:with(function(id) { return id }){([z1,,]);(window); }");
/*fuzzSeed-209835301*/count=436; tryItOut("v0 = (t1 instanceof m1);");
/*fuzzSeed-209835301*/count=437; tryItOut("Array.prototype.reverse.apply(this.a0, [a2]);\nv1 = g0.runOffThreadScript();\n");
/*fuzzSeed-209835301*/count=438; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((mathy0(( + ( + ( + 0x0ffffffff))), ( + Math.imul((y | 0), (Math.atan2(Math.fround(((y | 0) > (x | 0))), Math.fround(0/0)) | 0)))) , Math.fround(Math.pow(Math.fround(Math.cbrt(Math.fround(x))), Math.fround((mathy1((42 >>> 0), (y >>> 0)) >>> 0))))) >>> 0); }); testMathyFunction(mathy4, [2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -(2**53-2), 2**53-2, -Number.MAX_VALUE, -0, 42, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 1, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000000, 0, -1/0, 0x100000000, -(2**53+2), Math.PI, 0.000000000000001, -0x100000000, -0x080000000, 0x07fffffff, 0x080000001, 0x100000001, 0/0, 1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=439; tryItOut("length;\nt2.set(a1, v2);\n");
/*fuzzSeed-209835301*/count=440; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return ( + ( ! ( + Math.max((Math.cosh(( - y)) | 0), ( ! Math.asin(y)))))); }); testMathyFunction(mathy1, [1.7976931348623157e308, 1, 0x100000000, 0x100000001, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, -0x100000000, 2**53-2, -0x07fffffff, 1/0, 0x080000001, 2**53, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0.000000000000001, -0, -(2**53), -0x100000001, -(2**53+2), -0x080000000, Math.PI, 2**53+2, -1/0, 0/0, -Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-209835301*/count=441; tryItOut("\"use strict\"; yield \n( '' .watch(\"prototype\", Object.prototype.toLocaleString));");
/*fuzzSeed-209835301*/count=442; tryItOut("function shapeyConstructor(sfznsp){for (var ytqkzpfxn in this) { }for (var ytqrmvxta in this) { }this[\"__count__\"] = (({} = (void version(170))));if (Math.hypot( '' , x)) for (var ytqyqeats in this) { }for (var ytqfrizmn in this) { }Object.defineProperty(this, \"__count__\", ({get: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: undefined, has: SimpleObject, hasOwn: function() { throw 3; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; }), enumerable: false}));this[\"__count__\"] = x;Object.preventExtensions(this);this[\"__count__\"] = objectEmulatingUndefined();this[\"__count__\"] = (makeFinalizeObserver('nursery')) %= x;return this; }/*tLoopC*/for (let x of /*MARR*/[-0x080000000, (void 0), arguments, -0x080000000, -0x080000000, (void 0), arguments, arguments, arguments, (void 0), (void 0), s0 += s2;, arguments, s0 += s2;, arguments, arguments, (void 0), arguments, -0x080000000, -0x080000000, arguments, -0x080000000, s0 += s2;, -0x080000000, (void 0), arguments, s0 += s2;, arguments, (void 0), -0x080000000, s0 += s2;, (void 0), -0x080000000, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), s0 += s2;, arguments, s0 += s2;, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, -0x080000000, arguments, s0 += s2;, arguments, (void 0), -0x080000000, arguments, (void 0), s0 += s2;, s0 += s2;, arguments, -0x080000000, s0 += s2;, arguments, s0 += s2;, (void 0), arguments, (void 0), -0x080000000, arguments, -0x080000000, s0 += s2;, arguments, (void 0), -0x080000000, s0 += s2;, -0x080000000, s0 += s2;, (void 0), -0x080000000, arguments, arguments, (void 0), s0 += s2;, (void 0), -0x080000000, arguments, -0x080000000, -0x080000000, s0 += s2;, (void 0), -0x080000000, (void 0), -0x080000000, arguments, -0x080000000, s0 += s2;, (void 0), (void 0), arguments, (void 0), -0x080000000, s0 += s2;, arguments, s0 += s2;, arguments, (void 0), (void 0)]) { try{let djmnkg = shapeyConstructor(x); print('EETT'); for(var [d, a] =  /x/g  * true.throw(x) in x / c) print(djmnkg)}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-209835301*/count=443; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 2047.0;\n    return +((+(((((0xf67085a7)+(i0)) & (((((0xffffffff)) | ((0xfa93796f))) != (({x: true }))))) % (((((0xc82ec10)) ^ ((0xfb054a84))) / (abs((0x79b11259))|0)) >> (0x4ef89*((0x2757dc82))))) >> (((0x25358fdf) != (0x1add421b))))));\n  }\n  return f; })(this, {ff: Array.prototype.keys}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=444; tryItOut("Array.prototype.sort.apply(a0, [(function() { try { v1.__iterator__ = (function mcc_() { var moyrrk = 0; return function() { ++moyrrk; if (/*ICCD*/moyrrk % 8 == 1) { dumpln('hit!'); try { e2.has(i2); } catch(e0) { } try { v1 = r0.ignoreCase; } catch(e1) { } o2.v2 = t0.length; } else { dumpln('miss!'); try { s2 = new String; } catch(e0) { } a2.splice(NaN, v2); } };})(); } catch(e0) { } try { this.i1 = a2.entries; } catch(e1) { } i0 + ''; return g1.h1; })]);");
/*fuzzSeed-209835301*/count=445; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul(Math.min(Math.hypot(x, Math.acosh((y | 0))), Math.cos(y)), ((( ! Math.fround(( + y))) | 0) <= (Math.expm1(((( ! (Math.cosh(( + -Number.MIN_VALUE)) | 0)) | 0) >>> 0)) >>> 0))) * mathy2((y - x), Math.atan2((Math.acosh(( + (( + ( + y)) >>> 0))) >>> 0), Math.hypot((((Math.min(x, ((2**53 >>> 0) != y)) | 0) >>> 0) ^ (y >>> 0)), (Math.asin((Math.fround(mathy2(Math.fround(1/0), Math.fround(0x100000001))) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-209835301*/count=446; tryItOut("\"use strict\"; a1[/*UUV2*/(c.compile = c.freeze)];function c(d) { \"use strict\"; return (NaN++)() ? (/*UUV2*/(d.parseInt = d.setUint8)) : new RegExp(\"((?!(\\\\u00e3)+?))\", \"gym\") } (void schedulegc(g1));");
/*fuzzSeed-209835301*/count=447; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(( - Math.fround((Math.min(Math.fround(( + (( ! (x | 0)) | 0))), Math.fround(y)) >>> 0)))) !== (mathy0((Math.max(Math.hypot(Math.fround(Math.cosh(Math.fround(y))), Math.fround(( ~ Math.fround(y)))), 42) >>> 0), ( ! ( + (Math.ceil(((Math.imul((((2**53-2 >>> 0) << ((Math.sinh((x >>> 0)) >>> 0) >>> 0)) >>> 0), ((mathy0((x >> y), (mathy0(Math.fround(x), (x >>> 0)) >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000000, Math.PI, 1/0, 0/0, -0x080000001, 2**53+2, -(2**53-2), -1/0, 0.000000000000001, 42, Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, -0, 0x07fffffff, -0x100000000, -(2**53+2), 0, 2**53, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, 1, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=448; tryItOut("\"use asm\"; v2 = t2.length;");
/*fuzzSeed-209835301*/count=449; tryItOut("g1.t1[9];");
/*fuzzSeed-209835301*/count=450; tryItOut("a2 + '';");
/*fuzzSeed-209835301*/count=451; tryItOut("m2 + e2;");
/*fuzzSeed-209835301*/count=452; tryItOut("\"use strict\"; m2.get(o1.b2);");
/*fuzzSeed-209835301*/count=453; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=454; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=455; tryItOut("a1[let (c) window] = f0;");
/*fuzzSeed-209835301*/count=456; tryItOut("\"use strict\"; this.g2.a1[g1.v0] = 8.throw( /x/g );");
/*fuzzSeed-209835301*/count=457; tryItOut("\"use strict\"; x = e;");
/*fuzzSeed-209835301*/count=458; tryItOut("o0.g0.offThreadCompileScript(\"-14 != 27\");");
/*fuzzSeed-209835301*/count=459; tryItOut("/*infloop*/ for (arguments.callee.caller.caller.arguments of eval(\"/* no regression tests found */\")) {let (y) { Object.defineProperty(g1, \"v0\", { configurable: (x % 27 == 21), enumerable: true,  get: function() {  return a2.length; } });function x() { yield  \"\"  } b0 = new SharedArrayBuffer(0); } }");
/*fuzzSeed-209835301*/count=460; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.log2(( + Math.exp(Math.max(Math.fround(( - Math.fround(x))), (Math.tanh(-(2**53-2)) >>> 0)))))); }); testMathyFunction(mathy0, [(function(){return 0;}), [0], '', (new Boolean(false)), 0, false, '/0/', NaN, true, -0, ({valueOf:function(){return 0;}}), undefined, (new Number(0)), '\\0', 0.1, ({toString:function(){return '0';}}), (new String('')), /0/, objectEmulatingUndefined(), '0', 1, [], ({valueOf:function(){return '0';}}), (new Boolean(true)), null, (new Number(-0))]); ");
/*fuzzSeed-209835301*/count=461; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (((Math.max((( ! (Math.trunc(y) >>> 0)) >>> 0), (Math.atan2(( ! Math.pow(42, y)), (( + (Math.fround((y && 0)) ? y : (Math.max(y, -(2**53+2)) >>> 0))) >>> y)) >>> 0)) | 0) ? ((Math.log1p(Math.fround(Math.max(Math.fround(y), Math.fround(y)))) ? ( + Math.round(((Math.min((( + ((( ! ( + y)) | 0) <= y)) >>> 0), Math.fround(y)) >>> 0) & x))) : ( + ( + Math.fround(Math.abs(x))))) | 0) : (Math.acos(Math.fround(( ! ((y + Math.pow(y, ( ! x))) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy5, ['0', ({valueOf:function(){return 0;}}), true, (new Boolean(false)), '\\0', -0, ({toString:function(){return '0';}}), 0, objectEmulatingUndefined(), /0/, [], '/0/', 0.1, 1, (new Number(-0)), (function(){return 0;}), (new Number(0)), ({valueOf:function(){return '0';}}), undefined, (new String('')), [0], false, null, '', (new Boolean(true)), NaN]); ");
/*fuzzSeed-209835301*/count=462; tryItOut("t0 = new Int16Array(b2);c = Math.max(Math.exp(23), /*UUV1*/(x.cosh = Date.prototype.setSeconds));");
/*fuzzSeed-209835301*/count=463; tryItOut("\"use strict\"; z;");
/*fuzzSeed-209835301*/count=464; tryItOut("testMathyFunction(mathy1, [-0x0ffffffff, 42, -0x100000000, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, -(2**53-2), -0x080000001, 0x0ffffffff, -0x100000001, 1, Math.PI, -Number.MAX_VALUE, -(2**53), 0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, 1/0, -1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, -0, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, 0/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=465; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      (Int16ArrayView[0]) = ((0x6a078c19));\n    }\n    return (((0xb2588b4)))|0;\n    d1 = (d0);\n    return (((((0x6cc6462a)+((abs((((0x3f04c197)) | ((0xfc5e7611))))|0) > (((0xf53084ad)) & ((0xfba442f3)))))>>>(((~~(d0))))) / (((!(0xbb40315f)))>>>((0xa5e59c5b)+((((0xa20c832f))>>>((0xf84308dd))) > (((0xdc501378))>>>((0xf9c172a3))))+((0xb08da238))))))|0;\n  }\n  return f; })(this, {ff: (({} = case \"\\uC1AB\".throw(false): print(x);))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [({valueOf:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), (new Number(-0)), undefined, '/0/', ({toString:function(){return '0';}}), [], true, 1, -0, false, (function(){return 0;}), (new String('')), (new Boolean(true)), objectEmulatingUndefined(), (new Boolean(false)), '\\0', (new Number(0)), [0], '', NaN, null, '0', 0, /0/]); ");
/*fuzzSeed-209835301*/count=466; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53+2, 0x07fffffff, -(2**53-2), 1, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, -0, 0x080000001, 42, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x100000000, 0x0ffffffff, 0x100000000, -0x07fffffff, 0x100000001, 1/0, -Number.MIN_VALUE, -0x100000001, -1/0, 0.000000000000001, Math.PI, -(2**53)]); ");
/*fuzzSeed-209835301*/count=467; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.atanh(Math.min((( + (( ! (((x ? (x | 0) : (x | 0)) >>> 0) | 0)) >>> 0)) >>> 0), (( + ( ! ( + mathy0(((0 - x) | 0), ( + Math.atan(y)))))) | 0))), Math.fround((Math.pow(((Math.fround((Math.cosh(( + y)) | 0)) | 0) >>> 0), ( + Math.imul(( + -0x080000000), ( + Math.hypot(( + (( ~ (y >>> 0)) | y)), Math.fround(Math.sin((y | 0)))))))) >>> 0)))); }); testMathyFunction(mathy1, [(function(){return 0;}), 0, objectEmulatingUndefined(), 0.1, [0], [], 1, true, (new Number(0)), (new Boolean(false)), '\\0', -0, ({valueOf:function(){return '0';}}), NaN, ({valueOf:function(){return 0;}}), undefined, (new Boolean(true)), '0', /0/, (new Number(-0)), '', false, null, ({toString:function(){return '0';}}), (new String('')), '/0/']); ");
/*fuzzSeed-209835301*/count=468; tryItOut("\"use strict\"; /*oLoop*/for (xiawub = 0, b = this, eval; xiawub < 16; ++xiawub) { m0.get(this.o1.s1); } t2 + '';");
/*fuzzSeed-209835301*/count=469; tryItOut("Object.defineProperty(this, \"g2.a1\", { configurable: false, enumerable: false,  get: function() { /*RXUB*/var r = r1; var s = g2.s2; print(s.replace(r, function(y) { return r.__defineSetter__(\"s\", (new Function(\"o2.g0.f1 = o2.m0.get(h1);\"))) }, \"gy\"));  return o1.a0.filter((function(j) { f2(j); })); } });");
/*fuzzSeed-209835301*/count=470; tryItOut("\"use strict\"; v2 = evaluate(\"s1 += s2;\", ({ global: g2.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: /*MARR*/[function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call), function(){}, function(){}, function(){},  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call),  /x/g .__defineGetter__(\"e\", (b =>  { yield  ''  } ).call)].map, catchTermination: (x % 3 == 0) }));");
/*fuzzSeed-209835301*/count=471; tryItOut("\"use strict\"; t1[v2];");
/*fuzzSeed-209835301*/count=472; tryItOut("\"use strict\"; v2 = g2.eval(\"for(var [e, x] = /\\\\3[^]+?/yi in /*RXUE*/new RegExp(\\\"(\\\\\\\\b|\\\\\\\\1{1})|[][^]|\\\\\\\\1{2}{0}{2,}\\\", \\\"gyi\\\").exec(\\\"\\\")) Object.defineProperty(o1, \\\"v2\\\", { configurable: true, enumerable: x,  get: function() {  return t1.length; } });\");function x(d)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x628770ba)+(1)-(0x72976729)))|0;\n  }\n  return f;/* no regression tests found */");
/*fuzzSeed-209835301*/count=473; tryItOut("liiqvd();/*hhh*/function liiqvd( \"\"  = x, ...x){/*infloop*/ for  each(let x((4277)) in (window.yoyo(e\u0009))()) {this.g0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 3.777893186295716e+22;\n    var i3 = 0;\n    var d4 = 288230376151711740.0;\n    i1 = (/*FFI*/ff(((d4)), ((((i3)-(0xffffffff)) << ((i1)))), ((~~(((-((-((+abs(((Infinity))))))))) % ((+(((-0x1e552e3))>>>((0xd522c951)-(0xffffffff)-(0xcf3955bf)))))))), ((~~(d4))), ((((+abs((((Float32ArrayView[0])))))) / ((NaN)))), ((d4)), ((-9.671406556917033e+24)), ((4.722366482869645e+21)), ((+(1.0/0.0))), ((-2049.0)), ((9.0)))|0);\n    d4 = (134217727.0);\n    i0 = ((+(0x0)) < (((d2)) % ((6.189700196426902e+26))));\n    i1 = (i0);\n    d2 = (d4);\n    {\n      i1 = (0xf934e56c);\n    }\n    d2 = (+(-1.0/0.0));\n    i0 = (0xfcfaa015);\n    i0 = ((((((abs((((!(0xf92dcf91))-((0x539b5740) != (0x5d52c77f))-(0xffffffff)) ^ ((i3)+((0xffffffff))+(i1))))|0))))>>>(((0x2891ade6))+(0x17cbb452))));\n    return ((((4277))))|0;\n  }\n  return f; })(this, {ff: w}, new SharedArrayBuffer(4096)); }}");
/*fuzzSeed-209835301*/count=474; tryItOut("\"use strict\"; print(length);/*MXX3*/g0.Object.prototype.constructor = g1.Object.prototype.constructor;");
/*fuzzSeed-209835301*/count=475; tryItOut("/*ADP-1*/Object.defineProperty(a1, v0, ({enumerable: (x % 3 == 2)}));");
/*fuzzSeed-209835301*/count=476; tryItOut("/*RXUB*/var r = new RegExp(\"$\\\\s?\", \"gy\"); var s = [] = (4277); print(s.search(r)); ");
/*fuzzSeed-209835301*/count=477; tryItOut("\"use strict\"; m0.set(v2, i2);");
/*fuzzSeed-209835301*/count=478; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.imul((( ! Math.min(( + ( ! ( + x))), mathy1(Math.imul(x, x), y))) | 0), (Math.fround(Math.atan((x = let (b) b))) | 0)) | 0); }); testMathyFunction(mathy5, [-0, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, -0x100000000, -0x0ffffffff, 0x080000000, 0.000000000000001, Number.MAX_VALUE, -0x080000000, 42, -(2**53), 2**53-2, 0x100000000, 2**53, 1/0, 1, 0, -Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, 0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, -0x080000001]); ");
/*fuzzSeed-209835301*/count=479; tryItOut("var bwbpsb = new SharedArrayBuffer(3); var bwbpsb_0 = new Uint8Array(bwbpsb); print(bwbpsb_0[0]); print(\"\\u5AE2\" ? true :  \"\" );");
/*fuzzSeed-209835301*/count=480; tryItOut("L:for(var c = [] in x) print(x);");
/*fuzzSeed-209835301*/count=481; tryItOut("mathy1 = (function(x, y) { return (( - (( ~ Math.fround(Math.sinh((Math.pow((y >>> 0), ((Math.asin(((mathy0((x | 0), (y | 0)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0)))) >>> 0)) | 0); }); testMathyFunction(mathy1, [0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, -0, -0x07fffffff, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, 2**53+2, 2**53-2, 0x080000000, Math.PI, Number.MAX_VALUE, 42, 0.000000000000001, 0x080000001, -1/0, 1/0, -0x0ffffffff, 0x100000001, -(2**53), 1.7976931348623157e308, 0, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, 0/0, 1, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=482; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:[^\u23ae\u9a69\\r])/y; var s = \"\\u00a5\"; print(r.test(s)); ");
/*fuzzSeed-209835301*/count=483; tryItOut("\"use strict\"; Array.prototype.forEach.call(a2);");
/*fuzzSeed-209835301*/count=484; tryItOut("\"use strict\"; this.a0.push(o0.e2, e0);");
/*fuzzSeed-209835301*/count=485; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d1));\n  }\n  return f; })(this, {ff: String.prototype.toUpperCase}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=486; tryItOut("/*ADP-2*/Object.defineProperty(a2, 14, { configurable: new (function(y) { return /*RXUB*/var r = new RegExp(\"(?=(?:(?![^])|(?:[^\\\\ue8Dc\\\\xC5-\\\\n]\\\\u00ba?)(?:\\\\3)+))\", \"gyi\"); var s = \"\"; print(r.exec(s));  *= Float32Array(x) })((4277), ([(neuter.prototype) **= (4277)])), enumerable: encodeURIComponent.prototype, get: this.o0.f2, set: (function(j) { f2(j); }) });");
/*fuzzSeed-209835301*/count=487; tryItOut("i2 + '';");
/*fuzzSeed-209835301*/count=488; tryItOut("Array.prototype.unshift.call(this.a1, t1, o1.a2, f2, p2, g0.s2, ({a: window}), s0);");
/*fuzzSeed-209835301*/count=489; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(this.b0, \"toLocaleTimeString\", ({}));");
/*fuzzSeed-209835301*/count=490; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=491; tryItOut("m1.get(e2)\n/* no regression tests found */");
/*fuzzSeed-209835301*/count=492; tryItOut("\"use strict\"; m2 = new WeakMap;");
/*fuzzSeed-209835301*/count=493; tryItOut("\"use asm\"; testMathyFunction(mathy5, [-0x100000001, 42, 0x100000000, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, -1/0, -(2**53), -Number.MIN_VALUE, 1, 2**53, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -0, -0x100000000, -0x080000001, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -0x07fffffff, 2**53+2, 0, Number.MAX_VALUE, 0x07fffffff, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000001, 0x080000000, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=494; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + mathy0(( + Math.sqrt(( + Math.fround(Math.imul(Math.cosh(( + y)), Math.atan2(y, Math.fround(( ! Math.fround(x))))))))), ( ~ (( + Math.tanh(( + -(2**53-2)))) >>> 0)))), ( + mathy0((( ! (y | 0)) | 0), Math.asin((Math.trunc(( + (( + (mathy0(Math.max(Math.fround(y), Math.fround(y)), Math.fround(42)) | 0)) | (Math.pow(x, Math.fround(Math.imul(x, y))) | 0)))) >>> 0)))))); }); testMathyFunction(mathy1, [1, (new Boolean(false)), true, (new Number(0)), -0, ({toString:function(){return '0';}}), [0], objectEmulatingUndefined(), '\\0', (new String('')), (new Number(-0)), (new Boolean(true)), undefined, 0.1, NaN, null, false, (function(){return 0;}), [], '', '/0/', /0/, ({valueOf:function(){return 0;}}), '0', ({valueOf:function(){return '0';}}), 0]); ");
/*fuzzSeed-209835301*/count=495; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy3((Math.cos(mathy2(( - ( - (x >>> 0))), ( + x))) | 0), ( ~ ( + Math.sinh(( + x))))); }); testMathyFunction(mathy5, /*MARR*/[ 'A' , new Boolean(false), new Boolean(false), new Boolean(false), {}, new Boolean(false), new Boolean(false), {}, {}, -0x100000001,  'A' , {}, -0x100000001, -0x100000001, 1.7976931348623157e308, new Boolean(false), new Boolean(false), {},  'A' , {}, {}, 1.7976931348623157e308,  'A' , {}, 1.7976931348623157e308,  'A' , new Boolean(false), -0x100000001,  'A' , new Boolean(false), -0x100000001,  'A' , 1.7976931348623157e308, -0x100000001, 1.7976931348623157e308, -0x100000001, -0x100000001, 1.7976931348623157e308, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), {}, new Boolean(false), -0x100000001, -0x100000001, new Boolean(false), -0x100000001, {},  'A' , {}, -0x100000001,  'A' , -0x100000001, -0x100000001, 1.7976931348623157e308, {}, {}, {}, -0x100000001, {}, 1.7976931348623157e308, 1.7976931348623157e308, {},  'A' ,  'A' , new Boolean(false),  'A' , {}, 1.7976931348623157e308, -0x100000001, -0x100000001, new Boolean(false),  'A' , 1.7976931348623157e308, 1.7976931348623157e308, -0x100000001,  'A' , new Boolean(false), {}, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=496; tryItOut("mathy3 = (function(x, y) { return ( - ( + ( + (Math.atan2(Math.pow(mathy2(x, ((y >= Math.pow(y, y)) >>> 0)), ( + -Number.MAX_SAFE_INTEGER)), ((( + Math.sinh(Math.acosh(y))) && (Math.max((y | 0), ((( ! Math.fround(x)) | 0) | 0)) | 0)) | 0)) ? (( - (( - Math.cosh(x)) | 0)) >>> 0) : ( + Math.sin((x && ( + (Math.log1p(x) ? Math.fround((Math.fround(Math.pow(Math.fround(y), x)) >= Math.fround(y))) : -(2**53)))))))))); }); ");
/*fuzzSeed-209835301*/count=497; tryItOut("/*infloop*/do {--x; } while(\"\\u009C\");");
/*fuzzSeed-209835301*/count=498; tryItOut("/*bLoop*/for (var zjevkk = 0; zjevkk < 141; ++zjevkk) { if (zjevkk % 35 == 30) { print(new RegExp(\"[^]\", \"gy\")); } else { e0.delete(e2); }  } ");
/*fuzzSeed-209835301*/count=499; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( - (((Math.fround(Math.hypot((( + Math.pow(y, ( + y))) >>> 0), Math.clz32(y))) + Math.max(0x100000001, -0x07fffffff)) ? Math.sinh(( + ( + Math.atan((Math.cosh(y) | 0))))) : ( ~ Math.fround(Math.cbrt(Math.fround(0x0ffffffff))))) | 0))); }); ");
/*fuzzSeed-209835301*/count=500; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.log10((((((((( + Math.sqrt((Number.MIN_SAFE_INTEGER | 0))) | 0) | (x >>> 0)) | 0) >>> 0) ** ((Math.atan2((y | 0), (( + (1/0 >> ( + x))) >>> 0)) >>> 0) ? (Math.imul(x, (x | 0)) | 0) : mathy2(42, x))) ? (mathy3(-Number.MAX_VALUE, (Math.min(y, Math.fround(x)) | 0)) ? ( + 42) : Math.pow(y, y)) : ( ! Math.fround((( + ( + x)) === mathy1(Math.hypot(( + x), y), ( - ( + 1/0))))))) | 0))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -(2**53-2), 1/0, 1.7976931348623157e308, -0, -(2**53), 0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), 0/0, 0x0ffffffff, 0, -0x080000001, -0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000001, 1, 42, 0x100000000, 2**53-2, 0x080000001, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=501; tryItOut("m1.set(this.v0, b0)");
/*fuzzSeed-209835301*/count=502; tryItOut("\"use strict\"; g2.a2 = r2.exec(s2);");
/*fuzzSeed-209835301*/count=503; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.hypot((mathy0((((Math.fround(0x100000001) & (x >>> 0)) >>> 0) ** ( - x)), Math.fround(( + mathy0(( + (y * Math.fround(mathy0((y | 0), ((( + x) <= ( + x)) | 0))))), ( + y))))) >>> 0), Math.log1p(Math.atanh((Math.fround(x) <= (y | 0)))))); }); testMathyFunction(mathy1, [0.000000000000001, 0x100000001, -1/0, Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, -(2**53+2), 0, 0x07fffffff, 0/0, -0x080000000, -0, 0x0ffffffff, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, 1/0, 2**53+2, 1, -0x080000001, -(2**53), -0x100000001, 2**53, Number.MIN_VALUE, Math.PI, 0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=504; tryItOut("g0 = this;");
/*fuzzSeed-209835301*/count=505; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-209835301*/count=506; tryItOut("for(let [y, d] =  /x/g ( '' ) in /*FARR*/[z == x, , (void options('strict_mode')), , .../*MARR*/[false, [], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  '\\0' , false,  '\\0' ,  '\\0' , false, [],  '\\0' , [],  '\\0' ,  '\\0' ,  '\\0' , new Boolean(false), new Boolean(false), false, new Boolean(false), false, [], new Boolean(false), [], false, false, false, false,  '\\0' ]].filter((function shapeyConstructor(urgcvj){\"use strict\"; if ( \"\" ) this[\"codePointAt\"] = (-1/0);this[\"entries\"] = function(y) { return new RegExp(\"[^]\", \"gi\") };for (var ytqdwuvxc in this) { }Object.defineProperty(this, window, ({set: function(y) { \"use strict\"; yield y; s0.valueOf = (function() { i2.toString = (function() { try { v1.valueOf = (function(j) { f0(j); }); } catch(e0) { } const v1 = evalcx(\"\\\"use strict\\\"; mathy2 = (function(x, y) { return ( + Math.imul(( ~ ( + Math.hypot(( + ( ~ 1.7976931348623157e308)), ( + ( + Math.max(( + Math.atan2((y | 0), ((( + x) && (0.000000000000001 >>> 0)) >>> 0))), ( + y))))))), ( + (Math.tanh(Math.fround(0x100000001)) === (Math.atan2(( + 0x100000000), x) % x))))); }); testMathyFunction(mathy2, [0x080000000, 0x080000001, -1/0, 1.7976931348623157e308, Math.PI, -0, 0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, -0x080000000, -(2**53), -Number.MIN_VALUE, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, 0x07fffffff, 0, -0x0ffffffff, -0x100000001, 0/0, 1/0, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -(2**53-2), 0x0ffffffff, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE]); \", o1.g1); return b0; }); return h0; });; yield y; }, configurable: (urgcvj % 36 != 0)}));this[\"apply\"] = b;Object.defineProperty(this, \"keyFor\", ({writable: true}));return this; }).apply)) t1[v0];");
/*fuzzSeed-209835301*/count=507; tryItOut("s2 + '';");
/*fuzzSeed-209835301*/count=508; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=509; tryItOut("\"use strict\"; neuter(b2, \"change-data\");\nfunction ([y]) { };\n");
/*fuzzSeed-209835301*/count=510; tryItOut(" for (var d of true) {print(this.o1);continue L; }");
/*fuzzSeed-209835301*/count=511; tryItOut("var kilofz = new ArrayBuffer(4); var kilofz_0 = new Uint8ClampedArray(kilofz); kilofz_0[0] = 3; ( \"\" );\"\\u2D51\";");
/*fuzzSeed-209835301*/count=512; tryItOut("\"use strict\"; \"use asm\"; M: for  each(let d in x) a2.reverse(e2);");
/*fuzzSeed-209835301*/count=513; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=514; tryItOut("yield x;");
/*fuzzSeed-209835301*/count=515; tryItOut("/*bLoop*/for (let oagodf = 0; oagodf < 42; ++oagodf) { if (oagodf % 11 == 4) { s1 += 'x'; } else { a2.sort(); }  } ");
/*fuzzSeed-209835301*/count=516; tryItOut("/*RXUB*/var r = (4277); var s = \"\\u0094\"; print(uneval(s.match(r))); ");
/*fuzzSeed-209835301*/count=517; tryItOut("function f1(s2)  { return eval **= (eval(\"/* no regression tests found */\", [ \"\" ]//h\n).unwatch(x)) } ");
/*fuzzSeed-209835301*/count=518; tryItOut("\"use strict\"; t1 = t1.subarray(3, 10);");
/*fuzzSeed-209835301*/count=519; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( + Math.acos((Math.ceil(Math.fround((Math.log10(y) | 0))) >>> 0)))); }); testMathyFunction(mathy0, [Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, 0x100000001, -Number.MIN_VALUE, 2**53+2, 0x080000000, Number.MIN_VALUE, -0x100000000, 0, 42, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -1/0, -0x0ffffffff, 2**53, 0x0ffffffff, 0x100000000, -0, 0x07fffffff, Number.MAX_VALUE, 1/0, -(2**53-2), -0x100000001, -0x080000001, -0x080000000, 1, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=520; tryItOut("e1.has(g0.m1);");
/*fuzzSeed-209835301*/count=521; tryItOut("timeout(1800);");
/*fuzzSeed-209835301*/count=522; tryItOut("m0.has(e1);");
/*fuzzSeed-209835301*/count=523; tryItOut("\"use asm\"; /*ADP-3*/Object.defineProperty(a0, v1, { configurable: true, enumerable: false, writable: SyntaxError(/*MARR*/[[,,], [,,], 0.1]), value: o1.e2 });");
/*fuzzSeed-209835301*/count=524; tryItOut("\"use strict\"; this.h1.delete = Array.isArray.bind(f1);");
/*fuzzSeed-209835301*/count=525; tryItOut("\"use strict\"; v2 = evalcx(\"function f2(v0)  { yield x.unwatch(new String(\\\"10\\\")) } \", g1);");
/*fuzzSeed-209835301*/count=526; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"begin\" }); } g2.o0 = new Object;");
/*fuzzSeed-209835301*/count=527; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.asinh((Math.min((((mathy1(y, ( + (y >>> 0))) | 0) >= (Math.tanh((Math.fround(( + Math.fround(0x100000001))) - y)) | 0)) >>> 0), (Math.log2((Math.fround(Math.fround(Math.fround(x))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy4, [1/0, 2**53+2, -0x080000000, 1.7976931348623157e308, 0/0, 1, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, 0, 0x0ffffffff, -0, -0x07fffffff, -(2**53), -(2**53+2), 0x080000000, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -(2**53-2), 0x080000001, 0x07fffffff, -0x080000001, 2**53, -0x100000000, 0x100000000, -0x100000001]); ");
/*fuzzSeed-209835301*/count=528; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(\\\\s|[^][^\\\\d\\\\xc2]{2}(?!\\\\B{1,}))(?=(?:[^]))))|\\\\1\", \"gyim\"); var s = \"_aa \\n\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=529; tryItOut("for (var v of m1) { try { v2 = g0.g1.runOffThreadScript(); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\"; print(s.split(r)); print(r.lastIndex);  } catch(e1) { } ; }");
/*fuzzSeed-209835301*/count=530; tryItOut("\"use strict\"; switch(x) { case 5: default: a1.unshift(m0); }");
/*fuzzSeed-209835301*/count=531; tryItOut("a0.forEach((function() { for (var j=0;j<28;++j) { f1(j%2==0); } }), s2);");
/*fuzzSeed-209835301*/count=532; tryItOut("\"use strict\"; m1 = new WeakMap;");
/*fuzzSeed-209835301*/count=533; tryItOut("a2.reverse(b1);");
/*fuzzSeed-209835301*/count=534; tryItOut("f1.valueOf = (function() { e1.delete(o0.v2); return a2; });function x(x, ...window) { \"use strict\"; function shapeyConstructor(kgmymy){this[\"concat\"] = x;delete this[\"constructor\"];this[\"concat\"] = 'fafafa'.replace(/a/g, Function);delete this[\"blink\"];this[\"blink\"] = (eval) = new RegExp(\"[\\\\x75-\\\\xD1\\\\d\\\\S\\\\xd0]|\\\\1{4,8}\\\\3{17,18}*?\", \"gm\");this[\"constructor\"] = ({x:3});for (var ytqkcasvc in this) { }this[\"blink\"] = Int16Array;Object.defineProperty(this, \"constructor\", ({}));return this; }/*tLoopC*/for (let x of (/*MARR*/[true, true, [,,], [,,], [,,], true, true, true, [,,],  '' , true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, [,,], true, true, true, true, true, [,,], true, true, true, [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,], [,,],  '' ]) for (z of arguments)) { try{let uvqjfd = new shapeyConstructor(x); print('EETT'); o0.a0.sort((function(j) { if (j) { try { v2 = Array.prototype.some.apply(a2, [g1.f1, p0]); } catch(e0) { } try { neuter(b1, \"change-data\"); } catch(e1) { } try { v2 = this.t2[\"__lookupSetter__\"]; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(s2, g0); } else { this.o1.v0.valueOf = (function() { a0.unshift(s2, o0); return this.t1; }); } }), o2.a0);}catch(e){print('TTEE ' + e); } } } s2 + e0;[1];");
/*fuzzSeed-209835301*/count=535; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min((Math.trunc(((Math.max(((( + Math.log(x)) ? (y === Math.fround(Math.log(( + x)))) : ( + (( + ( - y)) >> ( + (Math.fround(x) <= ( + x)))))) | 0), (Math.fround((y || x)) | 0)) | 0) >>> 0)) >>> 0), Math.pow((Math.imul(( + (Math.sinh(((Math.acosh(( + ( + Number.MIN_SAFE_INTEGER))) >>> 0) >>> 0)) >>> 0)), ( + ( + Math.min(( - ((x / x) >>> 0)), (Math.max(((-0x080000001 != (y | 0)) | 0), y) | 0))))) | 0), Math.imul(x, ( + Math.fround((Math.fround((Math.hypot(-0x07fffffff, (y | 0)) | 0)) > Math.fround(Math.atan2(y, (y | 0))))))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -0, 1, -0x080000000, -(2**53), 0.000000000000001, -0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, -0x100000000, -0x0ffffffff, -1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000001, -(2**53+2), -(2**53-2), 0x080000001, 0/0, 0, 2**53, 0x080000000, 0x07fffffff, 0x100000000]); ");
/*fuzzSeed-209835301*/count=536; tryItOut("(makeFinalizeObserver('nursery'));");
/*fuzzSeed-209835301*/count=537; tryItOut("mathy1 = (function(x, y) { return Math.min(Math.fround(( ~ Math.fround(( ~ (((x < (Math.max(x, Math.fround(( ! x))) >>> 0)) ^ ( ! Math.fround(Math.max(x, x)))) >>> 0))))), Math.sqrt(Math.ceil(x))); }); testMathyFunction(mathy1, [0x080000000, Number.MIN_VALUE, -0x080000001, 0/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, -(2**53+2), -0x100000000, -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, 0x100000001, 1, -Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), 2**53-2, 0, 0x080000001, 1.7976931348623157e308, -(2**53-2), Number.MAX_VALUE, 0x100000000, 0.000000000000001, 42, -1/0, 2**53+2, 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=538; tryItOut("for (var p in g0) { try { s0 += s2; } catch(e0) { } b0.__proto__ = o0.s2; }");
/*fuzzSeed-209835301*/count=539; tryItOut("\"use strict\"; m0.get(p0);");
/*fuzzSeed-209835301*/count=540; tryItOut("M:if(false) v2 = Proxy.create(this.h2, a1); else {m2 + ''; }");
/*fuzzSeed-209835301*/count=541; tryItOut("mathy1 = (function(x, y) { return (( + ( + ( + ( + y)))) && Math.fround(Math.min((((( - ((( ~ (x >>> 0)) >>> 0) | 0)) | 0) || (0x100000000 >>> 0)) >>> 0), Math.fround((mathy0(Math.fround(Math.abs((Math.fround(( ! x)) | 0))), ( ~ (( ! (x | 0)) | 0))) | 0))))); }); ");
/*fuzzSeed-209835301*/count=542; tryItOut("\"use strict\"; if(eval = Proxy.createFunction(({/*TOODEEP*/})(\"\\u27FA\"), OSRExit, \"\\u253C\") >>  '' ) v2 = undefined; else  if ((4277)) {s1 += 'x'; }");
/*fuzzSeed-209835301*/count=543; tryItOut("testMathyFunction(mathy5, [0x07fffffff, Number.MAX_VALUE, -(2**53), Math.PI, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0x07fffffff, -0, 42, -0x0ffffffff, 1, 2**53+2, 0, 0.000000000000001, 0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, 1/0, 0/0, 0x100000000, -0x100000001, -Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -1/0]); ");
/*fuzzSeed-209835301*/count=544; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return Math.cos(( - Math.pow(Math.exp(x), Math.hypot(( + 0x0ffffffff), (y >> (y | 0)))))); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), new Boolean(true), ['z'], 1e-81, new Boolean(true), new Boolean(true), ['z'], 1e-81, 1e-81, new Boolean(true), ['z'], ['z'], new Boolean(true), ['z'], ['z'], ['z'], ['z'], new Boolean(true), ['z'], ['z'], new Boolean(true), 1e-81, new Boolean(true), new Boolean(true), 1e-81, ['z'], new Boolean(true), new Boolean(true), ['z'], 1e-81, 1e-81, new Boolean(true), ['z'], 1e-81, 1e-81, ['z'], 1e-81, new Boolean(true), new Boolean(true), new Boolean(true), 1e-81, ['z'], ['z'], 1e-81, ['z'], new Boolean(true), 1e-81, 1e-81, new Boolean(true), ['z']]); ");
/*fuzzSeed-209835301*/count=545; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.imul(Math.hypot((Math.imul(42, Math.acos((Math.imul(x, (( + x) | 0)) | 0))) | 0), Math.fround(( ~ (Math.hypot(( + Math.max(((Math.PI & ( + y)) >>> 0), x)), Math.fround(( ~ Math.abs(0)))) | 0)))), ( + Math.sign(( + Math.log1p(Math.fround((Math.min(( + (( + x) ^ ( + x))), x) >>> 0)))))))); }); testMathyFunction(mathy0, [0.000000000000001, Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 0x080000000, 0x07fffffff, -Number.MIN_VALUE, -(2**53), 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, Number.MIN_VALUE, 2**53+2, -0x080000001, -1/0, -0x100000000, -0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, -0x100000001, Number.MAX_VALUE, -(2**53+2), -0x080000000, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, 1, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, 2**53]); ");
/*fuzzSeed-209835301*/count=546; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=547; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0);");
/*fuzzSeed-209835301*/count=548; tryItOut("mathy0 = (function(x, y) { return ( + ( ! (( + 42) | ( - (Math.fround(x) / Math.fround(Math.sign(x))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, 1, -(2**53+2), 0x100000000, 42, 2**53+2, -(2**53), 0/0, 0x080000001, Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, -0x100000001, -0x080000001, -0, Math.PI, -0x080000000, -Number.MAX_VALUE, 1/0, 2**53-2, -0x100000000, 2**53, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-209835301*/count=549; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 256.0;\n    var d3 = -4294967297.0;\n    var i4 = 0;\n    var i5 = 0;\n    var d6 = 4194305.0;\n    var i7 = 0;\n    var i8 = 0;\n    return +((-1.9342813113834067e+25));\n    d2 = (+/*FFI*/ff(((((0x867edaed) / ((x)>>>((((-0x8000000))>>>((0xfd617351))) % (((0xffffffff))>>>((0x9a4e8b88)))))) << (((abs((((0x3966adf2) % (0x225a5fcf)) << ((-0x8000000)-(0xfdd57604)+(0xfe0e2879))))|0))+(0x24394428)+(/*FFI*/ff(((-((-1.5474250491067253e+26)))), ((((/*FFI*/ff(((3.8685626227668134e+25)))|0)) >> ((0xf818c8af)-(0xaa72b968)))), (((uneval(window)))), ((((0xf8f947ee)) ^ ((0xffffffff)))))|0)))), ((abs((((0x1f7f3a55)+((((-1.5)) % ((-8193.0))) > (+(1.0/0.0)))-(i4))|0))|0)), ((~~(d6))), (((((0x911bf40) ? (i0) : ((0x5477fe56) > (0x2b04b483)))) << ((i5)-((0x2d2d7c39))))), ((d6)), (((d6)))));\n    i7 = ((0xfb05e5ea) > (0x6f323bac));\n    {\n      {\n        {\n          i7 = (i1);\n        }\n      }\n    }\n    i0 = (i7);\n    return +((d2));\n  }\n  return f; })(this, {ff:  /x/g }, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[{}, {}, x, x, {}, {}, {}, x, new Boolean(true), new Boolean(true), {}, new Boolean(true), {}, new Boolean(true), {}, new Boolean(true), x, {}, x, {}, new Boolean(true), {}, x, x, {}, new Boolean(true), new Boolean(true), {}, x, x, {}, new Boolean(true), x, x, x, x, x, x, x, x, x, x, x, new Boolean(true), new Boolean(true), {}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, new Boolean(true), {}, new Boolean(true), x, new Boolean(true), x, new Boolean(true), {}, new Boolean(true), x, {}, x, {}, new Boolean(true), new Boolean(true), x, {}, new Boolean(true), x, {}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), {}, x, {}, {}, x, {}, x, new Boolean(true), x, x, {}, {}, new Boolean(true), x, {}, x, x, x, x, {}, x, new Boolean(true), new Boolean(true), x, x]); ");
/*fuzzSeed-209835301*/count=550; tryItOut("\"use strict\"; testMathyFunction(mathy4, [(new String('')), objectEmulatingUndefined(), 1, '\\0', '0', ({valueOf:function(){return '0';}}), '/0/', undefined, NaN, 0, ({toString:function(){return '0';}}), [0], (function(){return 0;}), -0, (new Boolean(true)), /0/, 0.1, (new Number(0)), ({valueOf:function(){return 0;}}), (new Number(-0)), true, '', (new Boolean(false)), false, [], null]); ");
/*fuzzSeed-209835301*/count=551; tryItOut("mathy3 = (function(x, y) { return ( + Math.sin((( + ( - Math.fround(y))) ^ y))); }); testMathyFunction(mathy3, [0/0, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, 2**53-2, 0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, -0, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000001, -0x07fffffff, 0x080000000, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -1/0, 0x100000000, -(2**53), -Number.MAX_VALUE, 0x100000001, 0, -0x080000001, 42, -(2**53+2), -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=552; tryItOut("this.v1 = t1.byteOffset;");
/*fuzzSeed-209835301*/count=553; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=554; tryItOut("mathy5 = (function(x, y) { return ( + ( ~ (Math.ceil(Math.fround(( + Math.sign(Math.expm1(Math.atan2(0.000000000000001, ( + -Number.MAX_SAFE_INTEGER))))))) | 0))); }); testMathyFunction(mathy5, [2**53, 0, 1/0, -0x100000001, -0x080000000, -0x07fffffff, -0, 0/0, -0x100000000, 0x100000001, 1, 0x07fffffff, 0.000000000000001, 2**53+2, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -1/0, 2**53-2, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000000, Math.PI, -(2**53), Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=555; tryItOut("/*tLoop*/for (let a of /*MARR*/[]) { o2.s1 += 'x'; }");
/*fuzzSeed-209835301*/count=556; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x07fffffff, 0x100000000, 0x080000000, 0x07fffffff, 0, 42, 2**53+2, -(2**53+2), -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, 1, Math.PI, 2**53-2, -0, 0x080000001, -(2**53), 1/0, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=557; tryItOut("mathy5 = (function(x, y) { return (( + (( + Math.sqrt((Math.atan2(mathy4((mathy3((y | 0), (y | 0)) | 0), Math.fround(mathy2(x, function shapeyConstructor(pnxxsx){this[\"a\"] = pnxxsx;if ((void version(180))) Object.defineProperty(this, \"a\", ({configurable: false, enumerable: true}));this[\"a\"] = y;delete this[\"prototype\"];delete this[\"getMilliseconds\"];if (pnxxsx) this[\"getMilliseconds\"] = function(){};Object.defineProperty(this, \"toSource\", ({enumerable: true}));delete this[\"getMilliseconds\"];this[\"getMilliseconds\"] = (new Function(\"this.g1.o1 + i2;\"));return this; }))), ( + -0x07fffffff)) % ( + -0x07fffffff)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x080000001, -0x080000001, 0.000000000000001, 1.7976931348623157e308, -0, -0x080000000, -0x100000001, 0x080000000, 0, 42, -(2**53+2), 0x100000000, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, -(2**53-2), Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, -(2**53), 1, -Number.MIN_VALUE, Math.PI, -1/0, -0x100000000]); ");
/*fuzzSeed-209835301*/count=558; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=559; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=560; tryItOut("a1.splice(6, ({valueOf: function() { a1.pop();return 0; }}));");
/*fuzzSeed-209835301*/count=561; tryItOut("print(v2);function z(y, a, y, y = 3, x, eval, window =  '' , NaN = undefined, x, w, x, x =  /x/g )\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-(objectEmulatingUndefined)));\n    d1 = (d1);\n    d1 = (+(1.0/0.0));\n    (Int16ArrayView[((i0)-(0xfa4dbe70)) >> 1]) = (((Uint16ArrayView[1])));\n    return +(((((+((d1)))) - ((+(-1.0/0.0)))) + (+atan2(((d1)), ((+abs(((Float32ArrayView[2])))))))));\n  }\n  return f;24;");
/*fuzzSeed-209835301*/count=562; tryItOut("/*vLoop*/for (let mkmbnl = 0; mkmbnl < 128; ++mkmbnl) { let a = mkmbnl; this.e2.has(this.o0); } ");
/*fuzzSeed-209835301*/count=563; tryItOut("v2 = evalcx(\"(this.__defineGetter__(\\\"eval\\\", NaN--))\", g1);");
/*fuzzSeed-209835301*/count=564; tryItOut("\"use strict\"; /* no regression tests found */b1 = t1.buffer;");
/*fuzzSeed-209835301*/count=565; tryItOut("\"use strict\"; a0.pop(v2);");
/*fuzzSeed-209835301*/count=566; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy2((Math.asinh(( + (( + ((x ? (x | 0) : Math.fround(x)) | 0)) ? ( + ( + (( + ( + ( - Math.fround(y)))) , ( + ((Math.fround(-Number.MAX_SAFE_INTEGER) - (Math.imul((y,  /x/  | 0), (y | 0)) | 0)) | 0))))) : x))) | 0), (((Math.asin(y) | 0) * (( + Math.atan2((Math.atan2(y, 0x0ffffffff) != (Math.log2(-0x0ffffffff) >>> 0)), ( + Math.asin(( + (y - ((Number.MAX_VALUE || x) | 0))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 0x080000000, -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000001, -0x080000001, Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, -1/0, 2**53+2, 0x07fffffff, -0x100000001, -(2**53+2), 0/0, 1/0, -Number.MAX_SAFE_INTEGER, 1, -(2**53-2), 2**53-2, 0.000000000000001, 2**53, -0x080000000, 42, 0x100000000, -0x0ffffffff, -0]); ");
/*fuzzSeed-209835301*/count=567; tryItOut("L:if((x % 9 != 1)) { if ((x)--) print((/*RXUE*//\\2.?/im.exec(\"\\n\\u31b6\\n\\u31b6\\ua2ff\\u00a11\\u0086\\u00cb \\ua2ff\\u00a11\\ua2ff\\u00a11\\ua2ff\\u00a11\\ua2ff\\u00a11\\ua2ff\\u00a11\\u5fe8\\n\\n\\u31b6\\n\\u31b6\\ua2ff\\u00a11\\u0086\\u00cb \\ua2ff\\u00a11\\ua2ff\\u00a11\\ua2ff\\u00a11\\ua2ff\\u00a11\\ua2ff\\u00a11\\u5fe8\")) = null\n);} else {o0.a1.forEach((function mcc_() { var tsmzds = 0; return function() { ++tsmzds; f2(/*ICCD*/tsmzds % 4 == 0);};})());selectforgc(o0);print(x); }");
/*fuzzSeed-209835301*/count=568; tryItOut("a0 = a0.concat(t0, this.i0, a0, b1);");
/*fuzzSeed-209835301*/count=569; tryItOut("\"use strict\"; /*RXUB*/var r = x; var s = \"\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\u2c52\\ud866\\n\\u698e\\ua806\\n\\n\\n\\u2c52\\ud866\\n\\u698e\\ua806\\n\\n\\n\\u2c52\\ud866\\n\\u698e\\ua806\\n\\n\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\n\\n\\n\\n\\n\\ua0d6\\u1eb1\\n\\u2c52\\ud866\\n\\u698e\\ua806\\n\\n\\n\\u2c52\\ud866\\n\\u698e\\ua806\\n\\n\\n\\u2c52\\ud866\\n\\u698e\\ua806\\n\\n\\u88d3\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=570; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(((((((0x0ffffffff | 0) ? (-Number.MAX_VALUE | 0) : (-0x080000000 | 0)) | 0) >>> 0) ^ Math.fround(mathy4(Math.fround((Math.cosh(( + Math.pow(y, ( + (-0x100000001 > x))))) | 0)), Math.fround((Math.ceil((mathy0(( + ( + -0)), Math.pow(x, (Math.pow((y >>> 0), (y >>> 0)) >>> 0))) | 0)) >>> 0))))) | 0), (((Math.fround(Math.cosh(Math.fround(( ~ (Math.log((y | 0)) | 0))))) >>> 0) - (( + Math.pow(( + ((-0x07fffffff - y) | y)), ( + y))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-209835301*/count=571; tryItOut("i2 + e0;\nv1 = evalcx(\"function f2(i0)  /* Comment */\\\"\\\\u9001\\\"\", g0);\n");
/*fuzzSeed-209835301*/count=572; tryItOut("\"use asm\"; function y(b)\"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((((i1)) ^ (((~~(-1099511627777.0)))+(i1))) != (abs(((\"\\uB420\") << (((Uint8ArrayView[2])) / ((-0xa251e*(0xc054f7aa))>>>((0xf8ef29ac)-(0x71a83ce0)-(0xba20d849))))))|0));\n    {\n;    }\n    i1 = (-0x8000000);\n    i0 = (0x507035a2);\n    (Int32ArrayView[2]) = ((i0)+(i1)-(i1));\n    switch ((imul((i0), (i1))|0)) {\n      default:\n        (Float32ArrayView[1]) = ((Infinity));\n    }\n    return ((((~~(+(0.0/0.0))))))|0;\n    return ((((imul((i1), (!(new (eval)(/*UUV2*/(c.filter = c.defineProperty)))))|0) <= ((((((+abs(((-4.835703278458517e+24)))) < ((4.835703278458517e+24) + (129.0))))>>>((+(((-0x8000000))>>>((0x54897c86)))))) % (((new RegExp(\"\\\\s\\\\B|\\\\b\", \"gi\"))+(i0))>>>((i1)*0x8a053)))|0))))|0;\n    return ((((70368744177664.0) < (+abs(((-7.737125245533627e+25)))))-(!(i0))))|0;\n  }\n  return f;print(x);(\"\\u4F74\");");
/*fuzzSeed-209835301*/count=573; tryItOut("switch(((yield (let (y = true ^=  '' ) x)))) { default: case 4: for (var p in a1) { t1[16] = b0; }break; case --x: i0.send(g0);case (4277) %= y: print((4277));break; break; a0.reverse();break; case ({e: (x += y)}):  }");
/*fuzzSeed-209835301*/count=574; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (d1);\n    d1 = (1152921504606847000.0);\n    return ((-0x2836e*(/*FFI*/ff(((-1.00390625)), ((-((Float64ArrayView[((i0)-(/*FFI*/ff(((0x3a6a7e87)), ((((-0x8000000)) << ((0xf87c3a35)))), ((-2147483648.0)), ((1.03125)), ((7.737125245533627e+25)))|0)) >> 3])))), ((-2049.0)), ((((-0x8000000)-(0xcbbce3df)+((0xa3041d52))) ^ ((0xb7339c80)-((-3.022314549036573e+23) != (-3.0))))), (((+(-1.0/0.0)))), ((d1)), ((+(-1.0/0.0))), ((+(-1.0/0.0))), ((-5.0)), ((2251799813685249.0)))|0)))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; new RegExp(\"\\\\3\", \"gyi\"); }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-1/0, -0x080000000, Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 2**53, 0/0, 42, 0x100000001, Number.MIN_VALUE, 2**53+2, -0, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 0x07fffffff, -0x100000001, 1, 1.7976931348623157e308, 0x100000000, -(2**53+2), 0.000000000000001, -0x07fffffff, 0, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=575; tryItOut("throw \"\\uDA8E\" ? this.__defineSetter__(\"eval\",  \"\" ) : x;for(let b of /*FARR*/[, timeout(1800), ([false]), , a = (({27:  \"\" , /*toXFun*/toString: function() { return w; } }))]) throw StopIteration;");
/*fuzzSeed-209835301*/count=576; tryItOut("mathy3 = (function(x, y) { return (( - ( ~ x)) >= Math.sinh(Math.fround(( + Math.fround(x))))); }); ");
/*fuzzSeed-209835301*/count=577; tryItOut("e2.add(m0);");
/*fuzzSeed-209835301*/count=578; tryItOut("e1.add(g0);");
/*fuzzSeed-209835301*/count=579; tryItOut("\"use strict\"; let (x) { Array.prototype.unshift.call(a2, x); }");
/*fuzzSeed-209835301*/count=580; tryItOut("m2 = a2[0];");
/*fuzzSeed-209835301*/count=581; tryItOut("mathy2 = (function(x, y) { return Math.atanh((( ~ ( + Math.fround(((Math.clz32(((x ? x : (x | 0)) >>> 0)) >>> 0) !== (mathy1((x | 0), (y | 0)) | 0))))) | 0)); }); testMathyFunction(mathy2, [null, ({toString:function(){return '0';}}), false, (new Number(-0)), -0, (new Boolean(true)), [0], /0/, NaN, '0', (function(){return 0;}), ({valueOf:function(){return 0;}}), '', (new Boolean(false)), 1, 0.1, ({valueOf:function(){return '0';}}), '\\0', true, 0, '/0/', (new String('')), undefined, [], objectEmulatingUndefined(), (new Number(0))]); ");
/*fuzzSeed-209835301*/count=582; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy3((Math.asin(Math.fround((((Math.pow(( + y), (Math.cosh((( + x) !== -0x07fffffff)) | 0)) | 0) >>> x) ^ x))) | 0), (mathy3((Math.acos(( + ( + ((x >>> 0) , ( + -1/0))))) | 0), (((( + x) >>> 0) < ( + ( ~ Math.fround((((((y >>> 0) >> (x >>> 0)) >>> 0) >>> 0) || Math.fround((( ! (x + -Number.MAX_SAFE_INTEGER)) | 0))))))) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-209835301*/count=583; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 0.000000000000001, -0x080000000, 2**53-2, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x100000000, -1/0, 0x080000000, 2**53, -0x100000001, -(2**53-2), 0/0, 1, -0x080000001, Math.PI, 0x0ffffffff, -(2**53), -0, 42, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, 0, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 1/0, 0x080000001]); ");
/*fuzzSeed-209835301*/count=584; tryItOut("for (var p in s0) { try { m2.has(h0); } catch(e0) { } for (var v of t1) { (void schedulegc(g0)); } }");
/*fuzzSeed-209835301*/count=585; tryItOut("/*oLoop*/for (let pzuafc = 0; pzuafc < 3; ++pzuafc) { break M;\nv1 = g0.eval(\"g0.o2.v1 = g2.t1.length;\");\n } ");
/*fuzzSeed-209835301*/count=586; tryItOut("\"use strict\"; /*MXX3*/g1.Symbol.prototype = g0.Symbol.prototype;function x(c = (function() { \"use strict\"; yield (let (w) new RegExp(\"((.))*\", \"gym\")); } })()) { m0.get(i0); } /*ODP-2*/Object.defineProperty(i2, \"getUTCDate\", { configurable: true, enumerable: (x % 2 != 1), get: (function() { v0 = g0.runOffThreadScript(); return o0; }), set: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = a9 * 7; print(a10); var r1 = r0 * a6; var r2 = 7 * a9; var r3 = 8 % a0; var r4 = 7 + x; var r5 = 4 * a7; var r6 = r4 ^ 4; a2 = 3 | 2; var r7 = a11 & r6; var r8 = a6 & r4; var r9 = r5 ^ a12; var r10 = a7 | a6; a12 = 4 + a6; var r11 = a2 | 5; var r12 = r7 % r7; var r13 = r12 & 0; var r14 = a11 + a12; var r15 = r10 - 3; var r16 = 0 - a5; var r17 = a4 % 6; print(r11); var r18 = a3 | a4; var r19 = r11 ^ r14; var r20 = 7 % r5; var r21 = a2 ^ 5; a10 = 5 % a3; var r22 = 8 - 7; var r23 = r8 + r4; var r24 = r1 | a7; var r25 = 7 * 7; var r26 = r9 * 0; var r27 = a10 & 6; var r28 = 0 & r2; print(r4); var r29 = r5 % a6; var r30 = r20 + r0; var r31 = r23 + 1; print(r6); var r32 = r25 * 3; a3 = r17 & r27; var r33 = a12 * r23; var r34 = r15 * 5; var r35 = 3 & r9; var r36 = 8 * a4; var r37 = 9 ^ r19; var r38 = 5 + r27; var r39 = r21 * a9; var r40 = r11 ^ r32; var r41 = 0 - 5; var r42 = 4 + a10; var r43 = r27 + 0; var r44 = r20 % a4; var r45 = r29 % 8; r43 = 4 - r5; var r46 = 1 | r14; var r47 = 6 * 6; var r48 = r9 / 9; r21 = r16 * a2; var r49 = r30 | 6; var r50 = 5 - r41; var r51 = a11 & a8; r29 = r10 & a12; var r52 = r49 ^ r43; r41 = r33 + r35; var r53 = r16 ^ a12; var r54 = a7 - a2; var r55 = r24 % r35; var r56 = r37 - a7; var r57 = 6 - r51; var r58 = r21 / r55; var r59 = r1 & 1; var r60 = r44 | r30; var r61 = r25 & r41; var r62 = r60 - r46; var r63 = 0 % r44; r60 = r22 * r41; r40 = a5 % r46; var r64 = r57 ^ 3; var r65 = r52 - r56; a3 = r41 ^ r22; r12 = a10 - r27; var r66 = 5 + r15; r13 = 6 / a7; var r67 = r7 | r9; var r68 = 4 - 9; var r69 = a1 & 8; var r70 = r47 * r46; var r71 = 6 / a8; var r72 = r5 - r68; var r73 = r33 % r65; var r74 = r28 | a10; var r75 = r67 + r66; var r76 = r15 | 4; var r77 = 0 / r15; print(r21); var r78 = 6 & 5; var r79 = r67 / 2; var r80 = a6 % 4; var r81 = r54 * 6; var r82 = 6 | r45; var r83 = r36 & 5; var r84 = 0 * x; var r85 = 7 % r56; var r86 = a1 / 8; var r87 = r51 | r35; print(r22); var r88 = r6 / r0; r14 = 5 * r20; var r89 = r50 & r61; var r90 = a7 - r2; var r91 = r23 & r11; r40 = 4 % 6; r21 = r75 % 6; var r92 = 6 / a0; var r93 = 6 & 7; var r94 = a1 ^ r43; print(a9); var r95 = 1 * 3; var r96 = r32 + r34; print(r86); r18 = a6 | r1; var r97 = r10 - r50; var r98 = r45 % 5; var r99 = r13 - r82; var r100 = r72 + r46; var r101 = r15 - r1; var r102 = a1 * r40; var r103 = r33 - r0; var r104 = a6 & 9; var r105 = a4 ^ a3; var r106 = r29 * 9; print(r38); var r107 = r23 * 6; var r108 = 4 | 6; r75 = r19 | a12; var r109 = 2 - r60; var r110 = r65 + r33; var r111 = 9 % 3; var r112 = r76 + r17; r49 = r22 | 5; var r113 = 3 / r62; var r114 = r108 % r15; var r115 = r88 % r95; var r116 = r108 ^ r42; var r117 = 4 / r13; r110 = 0 & 4; r26 = r65 % r75; return a12; }) });");
/*fuzzSeed-209835301*/count=587; tryItOut("mathy0 = (function(x, y) { return ((( + ((Math.max(((y <= Math.imul((y ? Math.fround((2**53+2 - x)) : y), x)) | 0), (Math.atan2((( + 0x100000000) >>> 0), x) | 0)) | 0) ** Math.acosh((Math.abs(( + y)) ? Math.acosh(x) : (Math.tan(Math.fround(Math.cosh(y))) >>> 0))))) & Math.fround(( ~ Math.sign((((y >>> 0) + ((((Math.expm1((x | 0)) | 0) || 0x080000001) | 0) >>> 0)) >>> 0))))) >>> 0); }); testMathyFunction(mathy0, [Math.PI, 0, -(2**53-2), 2**53+2, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -(2**53+2), 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, -1/0, 0x100000001, 0x100000000, -0x080000001, -0x080000000, Number.MIN_VALUE, -0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -0, 2**53]); ");
/*fuzzSeed-209835301*/count=588; tryItOut("mathy0 = (function(x, y) { return ( - Math.fround(( + Math.tan(Math.imul(Math.fround(( - (y !== y))), ((-0x07fffffff >= Number.MIN_VALUE) ** (y | 0))))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), 0, 1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 2**53, -(2**53+2), 0.000000000000001, -0, 2**53+2, -0x080000000, -0x100000001, 0x080000000, 0x07fffffff, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 42, 0x080000001, 2**53-2, -(2**53), 1, -1/0, 0/0, 0x100000000, 0x0ffffffff, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=589; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - ( - Math.fround(Math.atan2(Math.fround((((x | 0) ? (0x100000001 % Math.log2(y)) : (-0 >>> 0)) | 0)), ( + y))))); }); ");
/*fuzzSeed-209835301*/count=590; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((((( + ((-0 | 0) , ( + 0/0))) - ((( + ( + Math.fround(((y >>> 0) / Math.pow(y, x))))) >= (x | 0)) | 0)) ** ( + Math.fround(Math.sign(Math.fround((( + (x << (x >>> 0))) ? (Math.hypot(Math.fround((Math.sqrt((x | 0)) >>> 0)), (( + (y >> y)) >>> 0)) >>> 0) : (y | 0))))))) === ((((Math.hypot(y, (Math.clz32(((( ! y) | 0) | 0)) | 0)) >>> 0) <= (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) >> (Math.min((0x07fffffff ? Math.atan2(x, y) : (x >>> y)), (Math.max(( + Math.pow(( + 0.000000000000001), ( + x))), (x | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, Math.PI, -0x100000000, -0x100000001, 1, 0x100000001, 0.000000000000001, 0/0, 2**53-2, 2**53, 42, 1/0, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, Number.MAX_VALUE, -1/0, 0x0ffffffff, -0x080000000, 2**53+2, -(2**53), -0x080000001, 0x100000000, 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, 0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-209835301*/count=591; tryItOut("\"use strict\"; /*oLoop*/for (egbadu = 0; egbadu < 34; ++egbadu, (y)) { e1.toSource = (function() { try { i1 = new Iterator(i0); } catch(e0) { } try { a2.splice(NaN, arguments); } catch(e1) { } try { e0.has(i1); } catch(e2) { } s1 = new String; return g1; }); } ");
/*fuzzSeed-209835301*/count=592; tryItOut("with(intern((4277)))s0 += s1;");
/*fuzzSeed-209835301*/count=593; tryItOut("\"use strict\"; gigkxq((void shapeOf(({y}) = (4277))));/*hhh*/function gigkxq(){print(undefined);\nthis.m0.set(f0, i2);\n}\u0009");
/*fuzzSeed-209835301*/count=594; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=595; tryItOut("g0.a2.reverse(this.f1);");
/*fuzzSeed-209835301*/count=596; tryItOut("\"use strict\"; h1 + '';");
/*fuzzSeed-209835301*/count=597; tryItOut("\"use strict\"; if(false) { if ((4277)) {a2.push(a0);v1 = (f1 instanceof g1);{ void 0; void schedulegc(43); } Object.prototype.unwatch.call(f1, \"getTimezoneOffset\"); }} else {i1 + a1; }");
/*fuzzSeed-209835301*/count=598; tryItOut("\"use strict\"; e0.add(p1);");
/*fuzzSeed-209835301*/count=599; tryItOut("/*ADP-1*/Object.defineProperty(a0, 9, ({get: decodeURIComponent, set: Function, configurable: x}));");
/*fuzzSeed-209835301*/count=600; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! (Math.fround((Math.fround(Math.max(Math.asin(x), ((( - Math.min((( + (x >> ( + y))) >>> 0), y)) >>> 0) >>> 0))) ? 1.7976931348623157e308 : ( + ( - y)))) / ((( + Math.trunc(( + (Math.min(((Math.hypot((x | 0), (y | 0)) | 0) | 0), (x | 0)) | 0)))) | 0) <= ( + Math.sinh((((( ~ x) | 0) == (x | 0)) | 0)))))); }); ");
/*fuzzSeed-209835301*/count=601; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 131073.0;\n    i2 = (0x693515a1);\n    i2 = (0x85eaf3b0);\n    d0 = (d3);\n    (( /x/g  <<= /*UUV2*/(b.toFixed = b.getTime))) = (((~~(-590295810358705700000.0)) < (imul(((((-0x54514b7)) & ((-0x8000000))) > ((-(0xff5c9613))|0)), (0xffffffff))|0))+((0x6370469d) ? (0x87574f20) : (0x6ba35b))-(/*FFI*/ff(((((0x8f907d61)-((x) > (imul((0xfa72a4f4), (0xc8326757))|0))-(i2)) ^ ((0x33353da3)-(0x61e5cd65)))), ((((Math.max(0, x()))) & ((((0x84249da3)) & ((0xff3fe326))) % (((0xffffffff)) << ((0x1321a352)))))))|0));\n    {\n      (Uint32ArrayView[1]) = ((0xffffffff));\n    }\n    d3 = (((d3)) * ((NaN)));\n    d1 = (+/*FFI*/ff());\n    d1 = (+(0.0/0.0));\n    return (((0xf8fb0443)))|0;\n    d3 = (d0);\n    (Float64ArrayView[((((!(i2)))|0) % (0x342f5fc4)) >> 3]) = ((+(((abs(((0x8b486*(0x59e87ccc)) >> ((0x3091d79a)+(0x509befc2)+(0xf445a185))))|0) % ((-0x7dd4b*(0xbd1a8ed4)) | ((i2)-((0x6a249294)))))>>>((i2)+((+pow(((+(((68719476737.0) + (9007199254740992.0))))), (((-0x8000000) ? (549755813889.0) : (9.44473296573929e+21))))) > ((Uint16ArrayView[0])))))));\n    (Float32ArrayView[((/*FFI*/ff(((~~(+atan2((((33554433.0) + (-18446744073709552000.0))), ((d1)))))))|0)-((4277))) >> 2]) = ((d0));\n    return (((i2)))|0;\n    {\n      {\n        d3 = (Infinity);\n      }\n    }\n    return (((0xf848a3c9)))|0;\n  }\n  return f; })(this, {ff: Object.freeze}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 42, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0, -0x100000000, 0x100000001, -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 2**53, -0, -0x080000001, -(2**53), 0x07fffffff, Number.MAX_VALUE, -1/0, -(2**53+2), -0x07fffffff, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 1, 0x080000000, 2**53-2, 1/0, 0x100000000, -Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-209835301*/count=602; tryItOut("\"use strict\"; g1.v0 = Object.prototype.isPrototypeOf.call(g2, i0);");
/*fuzzSeed-209835301*/count=603; tryItOut("\"use strict\"; m0.set(v1, m0);");
/*fuzzSeed-209835301*/count=604; tryItOut("print(({__proto__: x, fontsize: let (dohrpw) y }));var saeqdm = new ArrayBuffer(16); var saeqdm_0 = new Int8Array(saeqdm); saeqdm_0[0] = -29; var saeqdm_1 = new Uint8ClampedArray(saeqdm); for (var p in g2.t2) { try { delete g1.h1.set; } catch(e0) { } try { v0 = evaluate(\"function f2(o0.g2)  /x/ \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: this, noScriptRval: false, sourceIsLazy: true, catchTermination: false, element: this.o2, elementAttributeName: s0, sourceMapURL: s2 })); } catch(e1) { } try { v0 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (saeqdm % 2 == 1), noScriptRval: (saeqdm_1[10] % 5 != 2), sourceIsLazy: true, catchTermination: false })); } catch(e2) { } /*RXUB*/var r = r1; var s = s0; print(r.exec(s));  }");
/*fuzzSeed-209835301*/count=605; tryItOut("(new RegExp(\"[^]\", \"im\"));print(x);\nt0 + '';\n");
/*fuzzSeed-209835301*/count=606; tryItOut("for (var v of f2) { try { v1 = g1.runOffThreadScript(); } catch(e0) { } v1 = evalcx(\"mathy4 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var ff = foreign.ff;\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    return ((-0xf3ae7*(/*FFI*/ff(((+(-1.0/0.0))), ((((((0x7f486f61)+(0xb17d24f)+(-0x8000000)) ^ (((-1.9342813113834067e+25) <= (36893488147419103000.0)))) % (~~((0xfac97b24) ? (-1.9342813113834067e+25) : (-4.835703278458517e+24)))) | ((i1)+((+(((-0x8000000))>>>((0x8e920972)))) >= (+(0.0/0.0)))))), ((((i0)))))|0)))|0;\\n  }\\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MIN_VALUE, -0x0ffffffff, 0x100000001, -0, 0x080000000, -0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, -0x100000001, -(2**53), Number.MAX_VALUE, 1/0, -1/0, Math.PI, -0x080000001, 42, 0x080000001, 0x07fffffff, 0, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 0x100000000, -0x080000000, 1, -Number.MIN_VALUE, -(2**53-2), 2**53-2, -(2**53+2)]); \", g1); }");
/*fuzzSeed-209835301*/count=607; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(o1, \"concat\", ({configurable: true}));");
/*fuzzSeed-209835301*/count=608; tryItOut("\"use strict\"; delete h0.getPropertyDescriptor;print(x);");
/*fuzzSeed-209835301*/count=609; tryItOut("( \"\" );\na1.pop({}, t0, p0);\n");
/*fuzzSeed-209835301*/count=610; tryItOut("v0 = (s2 instanceof s0);");
/*fuzzSeed-209835301*/count=611; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.expm1(Math.fround(Math.fround(Math.pow(Math.fround(Math.sign(-Number.MAX_SAFE_INTEGER)), Math.fround(Math.fround(Math.asin(Math.fround(( ~ y)))))))))); }); ");
/*fuzzSeed-209835301*/count=612; tryItOut("v1 = (i0 instanceof p0);");
/*fuzzSeed-209835301*/count=613; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.fround((Math.log10(y) >> (((( + Math.atan2(((y <= x) | 0), y)) >>> 0) >= (( - (x | 0)) >>> 0)) >>> 0))) <= (( + ( - ( + 1))) + Math.fround(( ! Math.fround(Math.fround((Math.abs(( + y)) ? Math.fround((x & x)) : ( + y)))))))); }); testMathyFunction(mathy5, /*MARR*/[false, [], false, [], false, [], [], false, [], false, false, [], [], false, [], false]); ");
/*fuzzSeed-209835301*/count=614; tryItOut("/*infloop*/for(let (/(\\1)/)(eval) in  \"\"  ^= \"\\uD830\") print([[]]\n);\nfor (var p in g2.p2) { h0.iterate = f1; }\n");
/*fuzzSeed-209835301*/count=615; tryItOut("if(false) {m0 + o1;return; } else print((void (Math.round(22))));");
/*fuzzSeed-209835301*/count=616; tryItOut("\"use strict\"; function shapeyConstructor(ssodpg){\"use strict\"; this[\"toLocaleString\"] = (function(x, y) { \"use strict\"; return (y === ( + ( + ( + y)))); });for (var ytqsvqytk in this) { }if ((4277)) this[\"arguments\"] = function shapeyConstructor(qyttcg){return this; };{ print(x); } return this; }/*tLoopC*/for (let b of encodeURI) { try{let stisrv = new shapeyConstructor(b); print('EETT'); ( /x/ );}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-209835301*/count=617; tryItOut("{ void 0; void relazifyFunctions('compartment'); }");
/*fuzzSeed-209835301*/count=618; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    i0 = ((((Float32ArrayView[((i3)) >> 2])) % ((-576460752303423500.0))) >= (+tan(((-22.valueOf(\"number\"))))));\n    i3 = ((-536870912.0) == (-36893488147419103000.0));\n    i2 = ((~((i3))));\n    return (((((((0x784e64a9)))|0) > (((i2)) ^ ((timeout(1800)))))))|0;\n  }\n  return f; })(this, {ff: (new Function(\"throw /*RXUE*/new RegExp(\\\"\\\\\\\\b{4,}\\\\\\\\b\\\\\\\\S{2,}|\\\\\\\\B+?[^]\\\\\\\\B|\\\\\\\\B(?=[\\\\uad91\\\\\\\\D\\\\u421d]{1,})+?|\\\\\\\\S+?\\\", \\\"gy\\\").exec(\\\"lll\\\\u0013\\\");\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -(2**53+2), 0x07fffffff, 0x080000000, 2**53-2, 0x100000000, 0x0ffffffff, -0x100000000, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, 1/0, -0x080000000, -(2**53), -0x0ffffffff, 0x100000001, 0x080000001, -1/0, -(2**53-2), 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, -0, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x100000001, 42]); ");
/*fuzzSeed-209835301*/count=619; tryItOut("i1.toString = f1;");
/*fuzzSeed-209835301*/count=620; tryItOut("v0 = evalcx(\"g1.v0 = evaluate(\\\"o1.o2 = s2.__proto__;\\\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: false }));\", g2);");
/*fuzzSeed-209835301*/count=621; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    switch ((abs((~((0xbb4c68f6) % (0xf883a7bd))))|0)) {\n      case -3:\n        {\n          i1 = (i0);\n        }\n        break;\n      case -2:\n        i0 = ((!((((i1)-(0xffffffff)) ^ ((i0))) < ((~~(-1.0625))))) ? ((((i1)+(i1))>>>((i1)-(i1)))) : (/*FFI*/ff(((-1.1805916207174113e+21)), ((576460752303423500.0)), ((2251799813685248.0)), (void x))|0));\n        break;\n    }\n    i0 = ((1.0625) == (513.0));\n    {\n      {\n        i1 = (0x5ad87c4b);\n      }\n    }\n    return +(((((i0) ? (65.0) : (+(0.0/0.0)))) * ((((Float32ArrayView[(0x8904d*(i0)) >> 2])) / ((-268435455.0))))));\n  }\n  return f; })(this, {ff: function \u000c(window, z =  /x/g (new RegExp(\"\\\\1\\\\2{4,5}|\\\\D*\", \"gi\")))x}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=622; tryItOut("e2.add(s0);");
/*fuzzSeed-209835301*/count=623; tryItOut("mathy1 = (function(x, y) { return ( + ( + ((( ~ (Math.acosh(((Math.max(( + y), x) ** (0x0ffffffff | 0)) | 0)) | 0)) ** ( + y)) | 0))); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-209835301*/count=624; tryItOut("/*infloop*/ for (let NaN of undefined) var x, c, x, kjowqo, vvlooj, a, yoltqt, bfhoya, ppbwxo;Math.sqrt");
/*fuzzSeed-209835301*/count=625; tryItOut("m1.delete(o2);");
/*fuzzSeed-209835301*/count=626; tryItOut("\"use strict\"; this.e0.has(h1)\n/*MXX1*/o1 = g2.Uint8Array.prototype.constructor;");
/*fuzzSeed-209835301*/count=627; tryItOut("o0.m2 = new Map;");
/*fuzzSeed-209835301*/count=628; tryItOut("this.a2 = r2.exec(o2.s2);");
/*fuzzSeed-209835301*/count=629; tryItOut("testMathyFunction(mathy3, [-1/0, -0, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 0x080000000, -(2**53+2), 0x07fffffff, 1/0, 1.7976931348623157e308, 2**53, 1, 0/0, -0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 0x100000001, 0x100000000, 0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, -(2**53-2), 0, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=630; tryItOut("a0.splice(NaN, 10);");
/*fuzzSeed-209835301*/count=631; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log(( + Math.expm1((Math.fround((Math.fround(Math.atan2(( + Math.asin(((((x | 0) === (x | 0)) >>> 0) | 0))), x)) ** Math.fround(( + (Math.min((Math.log2(x) | 0), (x | 0)) | 0))))) | 0)))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, Number.MAX_VALUE, 0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, -0, 1.7976931348623157e308, -(2**53+2), 0x100000000, -Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, -(2**53), 2**53, -0x080000001, 1/0, 0.000000000000001, -0x0ffffffff, 0x080000001, 2**53-2, -(2**53-2), -0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, 1, -0x07fffffff, 0/0, -1/0, -0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=632; tryItOut("s2.toString = (1 for (x in []));");
/*fuzzSeed-209835301*/count=633; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( - (mathy3(( + ( - y)), y) >>> 0))) >>> 0); }); testMathyFunction(mathy4, [1, 42, -0x100000001, 0x100000000, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, -Number.MAX_VALUE, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, 0x100000001, 0/0, 2**53, 1.7976931348623157e308, 2**53-2, 0x07fffffff, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, -(2**53+2), -0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -0x080000000, 0]); ");
/*fuzzSeed-209835301*/count=634; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a2, 12, { configurable: true, enumerable: false, writable: true, value: o2 });");
/*fuzzSeed-209835301*/count=635; tryItOut("\"use strict\"; /*infloop*/for(let x in (((1 for (x in [])))((\"\\uFCFB\".watch(\"sin\", new RegExp(\"[^]|[\\\\d\\\\v-\\u8b9b\\u00e7\\ua2bf-\\ub95c](?![\\u9d0c\\\\\\u17c4\\u5f75-\\\\ua3d8])+?|\\\\b*?|.{2}\", \"gy\"))))))v2 = r2.exec;");
/*fuzzSeed-209835301*/count=636; tryItOut("\"use strict\"; /*vLoop*/for (ansccz = 0; ansccz < 159; ++ansccz) { var z = ansccz; neuter(g2.g0.b0, \"change-data\"); } ");
/*fuzzSeed-209835301*/count=637; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -536870913.0;\n    var i3 = 0;\n    return (((i3)+(i3)))|0;\n  }\n  return f; })(this, {ff: WeakSet.prototype.add}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1.7976931348623157e308, 0x080000000, 0x080000001, 0x100000001, -1/0, 1, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 2**53, 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, 1/0, Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, Number.MAX_VALUE, 0.000000000000001, -0x100000000, -(2**53), 42, 0x07fffffff, -0, 0, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=638; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy2((((Math.acosh((mathy1((x | 0), (( + (Math.PI + -0x080000001)) >>> 0)) >>> 0)) >= (y - (Math.sqrt(-0) >>> 0))) >>> 0) >>> 0), ( + Math.min(( ~ Math.min((((x | 0) >> (-0x100000001 | 0)) | 0), 2**53)), Math.min((-(2**53) > y), (0x0ffffffff == ( + Math.acos(( + -Number.MIN_VALUE)))))))) >>> 0); }); testMathyFunction(mathy3, [-(2**53-2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, -(2**53), 0x07fffffff, 0.000000000000001, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 2**53+2, 2**53, -0x080000001, Number.MAX_VALUE, 0, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), 0x100000000, Math.PI, 2**53-2, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, -0, 0x080000000, 0x080000001, 42, -1/0, -0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=639; tryItOut("e2.delete(p2);");
/*fuzzSeed-209835301*/count=640; tryItOut("v2 = (this.g2 instanceof i2);");
/*fuzzSeed-209835301*/count=641; tryItOut("\"use strict\"; if(true) print(this.b2);f0(p2); else  if ( \"\" ) {/* no regression tests found */ }");
/*fuzzSeed-209835301*/count=642; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (((Math.exp(y) | 0) / Math.max(Math.fround(( + ((x >>> 0) * ( - x)))), (Math.sin((x >>> 0)) | 0))) % Math.hypot(((Math.max(y, Math.fround(Math.fround(Math.fround((x & (Math.min(y, x) >>> 0)))))) === ((((( + (x >>> 0)) | 0) ? (0/0 | 0) : Math.pow((Math.fround((( + Number.MAX_SAFE_INTEGER) ? ( + (( ~ Math.fround(x)) | 0)) : ( + y))) | 0), ((( + y) ? -Number.MIN_SAFE_INTEGER : ( + (((x >>> 0) / (-Number.MAX_VALUE >>> 0)) >>> 0))) >>> 0))) | 0) | 0)) | 0), ( ! ( + ( ~ y))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 0x07fffffff, 2**53+2, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, -0x100000000, 0x080000001, Math.PI, 1/0, -0, 0.000000000000001, -1/0, -0x07fffffff, 0, 0/0, 0x0ffffffff, -0x080000001, 1.7976931348623157e308, -(2**53-2), 2**53-2, 42, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53), -(2**53+2), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=643; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=644; tryItOut("m2.has(m0);");
/*fuzzSeed-209835301*/count=645; tryItOut("\"use strict\"; testMathyFunction(mathy0, [(new Boolean(false)), 0, NaN, 0.1, (new String('')), (function(){return 0;}), [0], (new Number(-0)), '/0/', '0', /0/, 1, objectEmulatingUndefined(), '', '\\0', null, ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), false, [], (new Boolean(true)), undefined, true, -0]); ");
/*fuzzSeed-209835301*/count=646; tryItOut("x = linkedList(x, 134);");
/*fuzzSeed-209835301*/count=647; tryItOut("/*vLoop*/for (var ffilgp = 0; ffilgp < 87; ++ffilgp) { w = ffilgp; {window;/*MXX2*/g0.Number.NEGATIVE_INFINITY = g1.i2; }\n(w = -5);\n } ");
/*fuzzSeed-209835301*/count=648; tryItOut("p1.valueOf = (function() { for (var j=0;j<85;++j) { this.f2(j%2==0); } });");
/*fuzzSeed-209835301*/count=649; tryItOut("\"use strict\"; for (var v of s2) { try { g2.offThreadCompileScript(\"\\\"use strict\\\"; a0.sort(f2);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: true, catchTermination: (x % 17 != 11) })); } catch(e0) { } p1.__proto__ = i1; }");
/*fuzzSeed-209835301*/count=650; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o1.o0, this.f0);");
/*fuzzSeed-209835301*/count=651; tryItOut("m0.set(b1, b2);");
/*fuzzSeed-209835301*/count=652; tryItOut("testMathyFunction(mathy0, [1, (new String('')), false, [], ({toString:function(){return '0';}}), 0, 0.1, (function(){return 0;}), undefined, '\\0', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), /0/, (new Number(-0)), true, null, (new Number(0)), (new Boolean(true)), objectEmulatingUndefined(), '/0/', '', NaN, -0, [0], (new Boolean(false)), '0']); ");
/*fuzzSeed-209835301*/count=653; tryItOut("/*infloop*/while(let (eval, x, x, c, eval, window, wcykqj)  /x/ )print(h1);");
/*fuzzSeed-209835301*/count=654; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1.1805916207174113e+21;\n    var d3 = 1.5;\n    var i4 = 0;\n    i0 = (0x53e382cf);\n    {\n      {\n        return ((((~((-0x8000000))) >= (((0xfe1d6c35)-(((-0x52f74d0) >= (0x5909f1a2)) ? ((0xa7a33547)) : ((0x1f39bc43) > (-0x8000000)))) >> (((abs((imul((0x58316368), (0xf81e823c))|0))|0) <= (((0x7fffffff) % (0x5aa1a155))|0))-(i1))))*0xb8cf2))|0;\n      }\n    }\n    d3 = (7.555786372591432e+22);\n    {\n      switch ((abs((((0x1bb55376)+(0xfb49223c)) | ((0x84ae2cf8)*0xfffff)))|0)) {\n        case 1:\n          i1 = (0xf5368db8);\n          break;\n        default:\n          i4 = ((+/*FFI*/ff(((((i1)) ^ (Int16Array()))), (((((d2) >= (((-7.555786372591432e+22)) / ((2.3611832414348226e+21))))) | ((0xff520c41)))), (((((((0xfc3fb9c6)+(0xfdefd97f)+(0x177dc5a1))>>>((i4))))+((-15.0) < (d3))))))) < ((17179869185.0) + (-4398046511104.0)));\n      }\n    }\n    {\n      d3 = (-1.888946593147858e+22);\n    }\n    return (((i1)-(i0)))|0;\n    {\n      {\n        d2 = ((+log(((\"\\uC975\")))));\n      }\n    }\n    {\n      i4 = (((((((0xffffffff))|0) > (((0xb931e8ba)-(0xffffffff)) << ((-0x10e485d)+(0x552b5c7f))))-((imul(((0x7fffffff) >= (0x3819b93c)), (i0))|0) == (~((0xcc0a42d8) / (0xd2c2ff24))))+((~~(36893488147419103000.0)))) ^ ((0xfc44b566)+(0xffffffff))));\n    }\n    return (((window)*0x210f5))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x080000001, 0x080000000, 2**53+2, -(2**53), -1/0, 42, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x080000000, 2**53, -0x100000000, -0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, 0x07fffffff, 0/0, -0x100000001, -0, -0x080000001, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, Number.MAX_VALUE, 1/0, -(2**53-2), 0]); ");
/*fuzzSeed-209835301*/count=655; tryItOut("testMathyFunction(mathy3, /*MARR*/[ /x/ ,  /x/ ,  /x/ , -0]); ");
/*fuzzSeed-209835301*/count=656; tryItOut("\"use strict\"; o1.g2 = m1;");
/*fuzzSeed-209835301*/count=657; tryItOut("xw = x;");
/*fuzzSeed-209835301*/count=658; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=659; tryItOut("mathy4 = (function(x, y) { return ( + Math.atan(( - ( ~ mathy2(y, ( + Math.atan2(x, Math.hypot(x, y)))))))); }); testMathyFunction(mathy4, [-1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 0x07fffffff, -0x080000000, 0x0ffffffff, -0x100000000, 0x080000001, -0x100000001, 0x100000001, 2**53+2, 0/0, 1.7976931348623157e308, 2**53, 1/0, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, 0x080000000, -0x080000001, -0x07fffffff, -0, 1, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), -0x0ffffffff, 0x100000000, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=660; tryItOut("(encodeURI());");
/*fuzzSeed-209835301*/count=661; tryItOut("if(true) {break L;print(x); } else (void schedulegc(g0));");
/*fuzzSeed-209835301*/count=662; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atan2(Math.min(( ! y), ( ! (Math.fround(( ~ x)) >>> 0))), ( + Math.log1p(mathy1((Math.imul(((Math.sin((x >>> 0)) >>> 0) >>> 0), y) >>> 0), (( - ( + (( + y) ? ( + ( + Math.atan(( + y)))) : ( + Math.fround(Math.ceil(Math.fround(y))))))) >>> 0)))))); }); testMathyFunction(mathy3, [0x080000001, -1/0, 0, -Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -0, -0x100000001, Math.PI, -(2**53), 42, 0x080000000, 0x100000000, 0x100000001, -Number.MIN_VALUE, -0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 1/0, 0x0ffffffff, 1, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 2**53+2, 0/0, 0x07fffffff, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=663; tryItOut("s2 = o2.g1.i2;");
/*fuzzSeed-209835301*/count=664; tryItOut("x = p2;");
/*fuzzSeed-209835301*/count=665; tryItOut("this.t2[11];");
/*fuzzSeed-209835301*/count=666; tryItOut("\"use strict\"; b0 = new SharedArrayBuffer(60);/*RXUB*/var r = /\\d/m; var s = x; print(s.replace(r, new ((4277).valueOf(\"number\"))((delete s.d), (eval).unwatch(\"8\")))); ");
/*fuzzSeed-209835301*/count=667; tryItOut("\"use strict\"; /*hhh*/function enlozy(){/*RXUB*/var r = r0; var s = \"3\"; print(uneval(r.exec(s))); print(r.lastIndex); }enlozy((4277));");
/*fuzzSeed-209835301*/count=668; tryItOut("\"use strict\"; this.b2 = new SharedArrayBuffer(60);");
/*fuzzSeed-209835301*/count=669; tryItOut("i1.send(o0.i1);");
/*fuzzSeed-209835301*/count=670; tryItOut("/*infloop*/M:for(((function fibonacci(qmxvar) { ; if (qmxvar <= 1) { ; return 1; } ; return fibonacci(qmxvar - 1) + fibonacci(qmxvar - 2);  })(5)); this ** -5\n; (new /*wrap3*/(function(){ \"use strict\"; var cybfku = (uneval(( /* Comment */new RegExp(\"(\\\\B{1,3}\\\\B\\\\u00B5?|[\\u8c01\\\\f\\\\w\\\\W]{3,2147483651}+){3,}\", \"gyi\")))); (Math.sinh)(); })())) M: for (let e of window) /*infloop*/for(var x = window ** \"\\uF440\"; undefined | arguments; ( /x/  >>= window)) {this.s2 = new String(i1); }");
/*fuzzSeed-209835301*/count=671; tryItOut(" for (var z of \"\\uFB36\") /*ODP-1*/Object.defineProperty(s1, \"apply\", ({value: (makeFinalizeObserver('tenured')), writable: true, configurable: false}));");
/*fuzzSeed-209835301*/count=672; tryItOut("\"use strict\"; testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), '0', (function(){return 0;}), /0/, (new Boolean(true)), undefined, '/0/', [], (new Boolean(false)), (new String('')), -0, ({toString:function(){return '0';}}), true, 1, [0], 0, 0.1, objectEmulatingUndefined(), '', ({valueOf:function(){return 0;}}), NaN, false, null, (new Number(-0)), (new Number(0)), '\\0']); ");
/*fuzzSeed-209835301*/count=673; tryItOut("for(let b in (function() { yield (4277); } })()) return  /x/g  /= /*UUV1*/(z.filter = function (c) { yield x } );");
/*fuzzSeed-209835301*/count=674; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=675; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(mathy0((( ! ((mathy0(y, (Math.fround(Math.hypot(( + ( + Math.min(( + (Math.log(Math.PI) ^ 1)), ( + y)))), Math.ceil(x))) >>> 0)) >>> 0) | 0)) | 0), mathy0(((( + (Math.hypot(y, (Math.fround(Math.atan2(((( - (x | 0)) | 0) >>> 0), Math.fround(y))) >>> 0)) % Math.cbrt(x))) ? (( ! ( + Math.round(x))) | 0) : ((mathy1(((( + Math.fround((Math.fround(( - Math.fround(y))) ? Math.fround(y) : Math.fround(y)))) | 0) >>> 0), ((Math.min(x, y) == (-0x100000001 >>> 0)) >>> 0)) >>> 0) >>> 0)) | 0), ( + (( - y) >= y))))); }); testMathyFunction(mathy2, ['/0/', (new Boolean(true)), '', (new String('')), true, null, 1, /0/, objectEmulatingUndefined(), -0, 0, '0', ({toString:function(){return '0';}}), [], (new Number(-0)), undefined, '\\0', NaN, [0], (function(){return 0;}), ({valueOf:function(){return '0';}}), 0.1, (new Number(0)), false, ({valueOf:function(){return 0;}}), (new Boolean(false))]); ");
/*fuzzSeed-209835301*/count=676; tryItOut("/*RXUB*/var r = r1; var s = g0.s0; print(s.split(r)); ");
/*fuzzSeed-209835301*/count=677; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-209835301*/count=678; tryItOut("for(let c of x) with({}) { print(g0); } for(let d in /*FARR*/[let (b = \"\\u6995\") this]) throw StopIteration;");
/*fuzzSeed-209835301*/count=679; tryItOut("\"use strict\"; h1.has = (function() { (++x).throw(new ( /x/ )(( '' .throw(-5))\n)) = t2[0]; return p0; });");
/*fuzzSeed-209835301*/count=680; tryItOut("a2.toString = (function mcc_() { var yzsliq = 0; return function() { ++yzsliq; if (/*ICCD*/yzsliq % 4 == 2) { dumpln('hit!'); try { this.g2.a1 + ''; } catch(e0) { } try { g2.v0 = Object.prototype.isPrototypeOf.call(h1, s0); } catch(e1) { } v2 = o0.t0.byteLength; } else { dumpln('miss!'); try { o0.p1 + ''; } catch(e0) { } /*ODP-1*/Object.defineProperty(p0, \"callee\", ({writable: (x % 6 == 5)})); } };})();");
/*fuzzSeed-209835301*/count=681; tryItOut("mathy0 = (function(x, y) { return Math.min(( ~ ((((Math.trunc((Math.fround(Math.atan2(Math.fround(Math.max(y, y)), Math.fround(-0x080000001))) >>> 0)) | 0) >>> 0) / ((((-(2**53-2) >>> 0) , 0) ? (Math.asinh((y >>> 0)) >>> 0) : y) >>> 0)) >>> 0)), Math.fround(Math.abs((((((((( + Math.trunc(( + x))) | 0) !== y) >>> 0) ? (((Math.fround(-0x080000000) , (Math.trunc(( + (y ? y : y))) >>> 0)) >>> 0) | 0) : (( ! Math.fround(Math.hypot(42, y))) | 0)) | 0) || ( + (y / ( + x)))) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), new Boolean(true),  '' , objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), -0, objectEmulatingUndefined(),  '' , new Boolean(true), new Boolean(true), -0, objectEmulatingUndefined(),  '' , new Boolean(true),  '' , objectEmulatingUndefined(),  '' , -0, -0,  '' , -0, new Boolean(true), -0, objectEmulatingUndefined(),  '' ,  '' , new Boolean(true), new Boolean(true),  '' , -0,  '' , objectEmulatingUndefined(), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true),  '' , new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), -0, objectEmulatingUndefined(), objectEmulatingUndefined(), -0, objectEmulatingUndefined(), new Boolean(true),  '' , objectEmulatingUndefined(),  '' , new Boolean(true), objectEmulatingUndefined(),  '' , new Boolean(true), new Boolean(true), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(), new Boolean(true),  '' ,  '' , objectEmulatingUndefined(), -0,  '' , objectEmulatingUndefined(), -0, objectEmulatingUndefined(),  '' , objectEmulatingUndefined()]); ");
/*fuzzSeed-209835301*/count=682; tryItOut("b2 = new ArrayBuffer(56);");
/*fuzzSeed-209835301*/count=683; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -3.094850098213451e+26;\n    var d3 = -67108865.0;\n    i1 = (0x6d07daed);\n    d3 = (d2);\n    i1 = (0x8e076663);\n    return ((-((((i0)) & ((0x71fffe50) / (0x0))))))|0;\n  }\n  return f; })(this, {ff: (function(y) { yield y; e1.has(i0);; yield y; }).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000001, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, 1, 1/0, -0x100000000, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 42, Number.MIN_VALUE, 2**53-2, -0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -0x100000001, -0x07fffffff, 0x0ffffffff, -0x080000000, -0x080000001, 0, Number.MAX_VALUE, -(2**53+2), 0x100000000, Math.PI, 2**53]); ");
/*fuzzSeed-209835301*/count=684; tryItOut("\"use strict\"; let(x) ((function(){throw eval;})());let(y) { return;}");
/*fuzzSeed-209835301*/count=685; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=686; tryItOut("\"use asm\"; eval = linkedList(eval, 1131);");
/*fuzzSeed-209835301*/count=687; tryItOut("L: {m1.has(i0); }");
/*fuzzSeed-209835301*/count=688; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.fround(Math.fround((Math.fround(( + (Math.imul((y | 0), (y | 0)) | 0))) ** Math.fround(Math.cos(Math.imul(1.7976931348623157e308, ( ~ 0x07fffffff))))))) >> (mathy1(((( - (y | 0)) ** (x >>> 0)) >>> 0), ( ! ((0 >> ( + (( - (y | 0)) | 0))) | 0))) / Math.max((( + ((( ~ (x | 0)) | 0) >>> 0)) >>> 0), Math.pow(y, ( + ( + Math.max((y >>> 0), ( + mathy1((y | 0), x))))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, Number.MIN_VALUE, -1/0, Math.PI, -(2**53), -0x080000001, -0x100000001, -0x080000000, 1.7976931348623157e308, -(2**53+2), 2**53-2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, 2**53, 0.000000000000001, 0, 0x0ffffffff, -0, 2**53+2, 1/0, 42, 0/0, 0x07fffffff, -0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-209835301*/count=689; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return Math.fround(Math.pow(Math.fround(( + Math.atan(( + Math.hypot((2**53+2 >>> 0), (( + ( ~ ( + ( - ((Math.min((x >>> 0), (y >>> 0)) >>> 0) >>> 0))))) ? (Math.tan(y) >> (y >>> 0)) : Math.ceil(Math.fround(0)))))))), Math.fround(( - (Math.atan2(0x100000001, ( + Math.clz32(1/0))) | 0))))); }); testMathyFunction(mathy3, [-0x07fffffff, 0/0, 2**53-2, 0x080000000, -0x100000000, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -0x080000000, 1/0, 0x100000001, 0x100000000, -0, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, 42, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), 2**53]); ");
/*fuzzSeed-209835301*/count=690; tryItOut("v2 = r2.unicode;");
/*fuzzSeed-209835301*/count=691; tryItOut("b0 = g0.t1.buffer;");
/*fuzzSeed-209835301*/count=692; tryItOut("if((x % 18 != 9)) {/*MXX2*/g2.String.raw = g0.i0;/* no regression tests found */ } else  if ((({\"4\": (void version(180)), eval: 19 }))) {m2.get(this.t1); } else {while((((function factorial(qwzmhf) { ; if (qwzmhf == 0) { ; return 1; } ; return qwzmhf * factorial(qwzmhf - 1);  })(59444))) && 0)this.b2.toString = f0; }");
/*fuzzSeed-209835301*/count=693; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.imul(((Math.log1p(-Number.MAX_VALUE) | 0) % Math.atan2(((y | y) | 0), (y ? (y >>> 0) : x))), (( - (-0x0ffffffff >> y)) ** ( + mathy1(( + 1.7976931348623157e308), ( + ( - x)))))) <= ( + Math.log1p(( + mathy0(( ~ x), (y ? x : 1/0)))))); }); testMathyFunction(mathy2, /*MARR*/[(0/0), (0/0), eval, (0/0), (0/0), true, true, (0/0), undefined, eval, eval, undefined, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, true, (0/0), undefined, (0/0), true, eval, true, eval, eval, true, (0/0), (0/0), (0/0), (0/0), eval, eval, (0/0), true, eval, (0/0), (0/0), (0/0), true, true, eval]); ");
/*fuzzSeed-209835301*/count=694; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((((( ! (((x | 0) ? (Math.sin(x) < Math.log2(-Number.MAX_VALUE)) : (Math.max(y, ( + (Math.fround(Math.imul(Math.fround(x), Math.fround(y))) > Math.fround(1.7976931348623157e308)))) >>> 0)) | 0)) | 0) >>> 0) || ((( ! ((y , (x | 0)) >>> 0)) < Math.acos(( + ( + Math.atan2((Math.fround(( + Math.fround((x !== y)))) | 0), ((x / ( + y)) | 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, 0x100000001, -Number.MAX_VALUE, -(2**53-2), -(2**53), 0x080000001, 2**53-2, -0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, 1/0, 0x100000000, 2**53+2, 42, -(2**53+2), 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 2**53, -0x080000001]); ");
/*fuzzSeed-209835301*/count=695; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x100000001, 1.7976931348623157e308, -0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53, 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 42, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, -(2**53), -0, -1/0, -Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, Number.MAX_VALUE, Math.PI, -0x07fffffff, -(2**53-2), -Number.MIN_VALUE, -0x080000001, -(2**53+2), 0x100000000, Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, 1, 0x080000000]); ");
/*fuzzSeed-209835301*/count=696; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -18014398509481984.0;\n    var i3 = 0;\n    var d4 = -536870913.0;\n    var i5 = 0;\n    i0 = ((0xf1e2c6f9));\n    (Float32ArrayView[((i0)+(0xddaf6a68)) >> 2]) = (((/*FFI*/ff(((-0x457c519)), ((+((((0xc20cccb8) == (0xa90c703a))*0xc2743)>>>((0x131ab977)+(-0x8000000)+(0xf6242093))))), (((((0xfe325aec) ? (-0x76002c2) : (0xffffffff))-(0xff57b93f)) & ((0xffd36ec4)-(0x9deaa303)-(0x3d0783a3)))), ((0x1674fc02)), ((+(((0xa6087a62)) ^ ((0xfe64fc2d))))), ((~((0xa3727d8)))), ((-1.125)), ((-1.00390625)), ((-17179869185.0)), ((-73786976294838210000.0)))|0) ? (-((Float32ArrayView[2]))) : (d2)));\nprint(x);    {\n      (Float32ArrayView[((0xfed5917c)) >> 2]) = ((73786976294838210000.0));\n    }\n    {\n      i0 = (0xfb552615);\n    }\n    i5 = (i5);\n    i0 = (i0);\n    i3 = (((((i1) ? (-18446744073709552000.0) : (d4)))) <= (-36028797018963970.0));\n    return (((i3)+((((((0x3c027c7b)-(0x67acbed5)+(0x192e953e)) & ((0xf9ac174c))) % (((-0x8000000)-(0x6776fa5e)-(0xaa4016b4)) ^ ((0x10eb3f7f)))) >> ((( /x/ .valueOf(\"number\")))-(i5)+(i5))))))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=697; tryItOut("mathy3 = (function(x, y) { return (( ~ ((Math.min(( + ( + Math.abs(( + y)))), Math.fround(((y >= 0x100000000) && 1))) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0, -(2**53+2), 0x100000001, 0x07fffffff, -1/0, 2**53, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 0x100000000, 42, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, 1, Math.PI, -0x100000000, -0x080000001, 2**53+2, 0x080000000, 2**53-2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 1/0]); ");
/*fuzzSeed-209835301*/count=698; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.log10(( + Math.fround(Math.atanh(Math.fround(mathy2(y, Math.atan(Math.fround(0x080000001)))))))) >>> 0); }); testMathyFunction(mathy4, [2**53+2, -1/0, 2**53, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 0x100000000, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, 1.7976931348623157e308, -(2**53), -0x100000000, -0x100000001, Math.PI, -0x080000001, 1/0, 0x100000001, 0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, 0, -0, 42, -(2**53-2), -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=699; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.min((Math.pow((Math.hypot(Math.asin(Math.clz32(( + Number.MAX_SAFE_INTEGER))), (Number.MIN_SAFE_INTEGER >= x)) >>> 0), ((( + Math.fround(y)) - Math.acosh(( - (1 | 0)))) >>> 0)) >>> 0), Math.min(Math.fround(Math.fround(mathy0(Math.fround(1/0), y))), (( + Math.sqrt(Math.fround(x))) | ( + Math.pow((y | 0), (y * y)))))) - ( + Math.fround(((Math.expm1((Math.imul(y, Math.fround(Math.sin(x))) | 0)) >>> 0) != Math.abs((Math.fround((mathy4((( ~ x) >>> 0), (y >>> 0)) >>> 0)) ** Math.fround(( + Math.fround((((x >>> 0) ? (y >>> 0) : y) >>> 0)))))))))); }); testMathyFunction(mathy5, [2**53, Number.MIN_SAFE_INTEGER, -(2**53), 0/0, 0x080000000, Math.PI, 2**53+2, 0, -0, -0x100000001, 2**53-2, Number.MIN_VALUE, 1/0, 0x100000000, 1.7976931348623157e308, 0x100000001, -0x07fffffff, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), -1/0, -(2**53-2), 0x07fffffff, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 42, 0x080000001, Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=700; tryItOut("mathy1 = (function(x, y) { return (mathy0((mathy0(Math.fround(Math.acosh(-0x0ffffffff)), ( + (( + -0) * (x <= ( + (( + ((x >>> 0) <= 0x100000001)) << (-Number.MAX_SAFE_INTEGER | 0))))))) | 0), (((Math.atan2(mathy0(Math.min(( - x), -0), (mathy0((y | 0), (-0 | 0)) | 0)), Math.fround(Math.sin(x))) | 0) >>> 0) >> (((Math.cos(((-Number.MAX_SAFE_INTEGER < ( + -0x100000000)) , y)) >>> 0) % Math.sinh((((y | 0) <= (x | 0)) | 0))) >>> 0))) | 0); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 0x100000001, 2**53, -0x07fffffff, 42, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, -(2**53+2), 0x0ffffffff, 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, -0x100000001, 0.000000000000001, -(2**53), Math.PI, 0x07fffffff, -0x080000000, 1/0, 2**53+2, 1.7976931348623157e308, -1/0, -0, Number.MAX_VALUE, 0, 2**53-2, 0/0, 0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=701; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((((((Math.fround(Math.atan((( ~ -Number.MIN_VALUE) | 0))) >>> 0) <= ((Math.min((( ! (x | 0)) | 0), (( ! x) | 0)) | 0) >>> 0)) >>> 0) | 0) <= ( - x)) | 0) ? Math.atan2(Math.cosh((( ~ ( + (( + 0x07fffffff) && x))) | 0)), Math.tanh((mathy2((y >>> 0), (mathy2((x >>> 0), (Math.imul(( + Math.atan2(( + y), y)), x) >>> 0)) >>> 0)) >>> 0))) : (( + Math.fround(y)) && Math.min((Math.clz32(x) | 0), Math.fround(x)))); }); testMathyFunction(mathy3, [0x080000000, Math.PI, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), -Number.MAX_VALUE, 1/0, 0/0, -(2**53+2), -0x100000000, 0x080000001, 1, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, -(2**53-2), 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, -0x0ffffffff, 0.000000000000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, -0x080000001, 2**53-2, 2**53, 42, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=702; tryItOut("mathy0 = (function(x, y) { return Math.max(( + ( ~ Math.fround(((Math.max(Math.fround(( - y)), ((Math.exp(0x0ffffffff) >>> 0) >>> 0)) | 0) >> (x | 0))))), Math.fround((Math.fround((( ~ (( ~ ( + x)) ? (((y >>> 0) <= Math.fround(Math.PI)) >>> 0) : (( ! ( + Math.clz32(0x0ffffffff))) >>> 0))) % (((( + ( + Math.log2(( + 1.7976931348623157e308)))) ? Math.imul(Math.fround(Math.min(Math.fround(y), Math.fround(function shapeyConstructor(mdtaja){\"use strict\"; Object.defineProperty(mdtaja, \"1\", ({writable: (x % 2 == 0)}));if (\"\\u8147\") { print((function ([y]) { })()); } Object.defineProperty(mdtaja, \"keys\", ({set: /*wrap3*/(function(){ var kkvpzi = window; (function(y) { continue M; })(); }), configurable: (mdtaja % 6 != 2), enumerable: true}));mdtaja[18] = URIError.prototype.toString;if (mdtaja) mdtaja[18] = (let (e=eval) e);{ this.v2 + this.g1; } mdtaja[\"x\"] = /\\2+?/gyim;if ({}) for (var ytqocrxjt in mdtaja) { }return mdtaja; }))), x) : y) >>> 0) * (x / y)))) ^ Math.fround(( ~ (Math.tanh(x) | 0)))))); }); testMathyFunction(mathy0, [-0x080000001, 42, 0x100000000, 2**53+2, Math.PI, 0x100000001, 1.7976931348623157e308, 0x080000000, 1, -Number.MAX_VALUE, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 2**53-2, 0x0ffffffff, -1/0, -0x100000001, -0x100000000, 0x080000001, 2**53, -(2**53-2), 0.000000000000001, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, -(2**53), Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=703; tryItOut("g2.offThreadCompileScript(\"/* no regression tests found */\");\nprint(uneval(f1));\n");
/*fuzzSeed-209835301*/count=704; tryItOut("({x: [window], x}) = /*UUV1*/(c.toLocaleUpperCase = encodeURIComponent);");
/*fuzzSeed-209835301*/count=705; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (-0x8000000);\n    d0 = (d0);\nprint(x);    i1 = (-0x8000000);\n    {\n      (Uint16ArrayView[((((0xaac56b03)) ? ((-0x8000000) ? (0xffffffff) : (0x1b42ca14)) : (0xfe86ae5c))+(i1)) >> 1]) = ((Uint8ArrayView[1]));\n    }\n    return (((((((Uint8ArrayView[2]))|0) % (((/*FFI*/ff(((68719476737.0)))|0)-(i1)) >> (-(0x2f6fcb3e)))) << ((0x27a34851) / (-0x29b527e))) % (~~(d0))))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x07fffffff, -0x100000000, 0x080000001, -0, -0x080000000, 1.7976931348623157e308, 0x100000000, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 0, -0x0ffffffff, 0.000000000000001, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 2**53-2, 1, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 0x100000001, 42, 2**53, -0x100000001, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-209835301*/count=706; tryItOut("Array.prototype.sort.call(g0.a2, (yield x), g2.e1);");
/*fuzzSeed-209835301*/count=707; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ (Math.cbrt((((x + ( + ((1/0 ? y : y) << 1))) < y) | 0)) | 0)); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, -(2**53-2), 0x100000000, 0x080000000, Math.PI, 0.000000000000001, -0x080000001, -1/0, 0, 0/0, 1, -(2**53), 0x0ffffffff, 2**53, 42, 1/0, -(2**53+2), -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -0x100000000, -0x0ffffffff, 0x100000001, -0x080000000, 0x080000001, -Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=708; tryItOut("mathy0 = (function(x, y) { return ( - Math.hypot(((Math.asinh(((y ** (x >>> 0)) >>> 0)) >>> 0) ? (x - (y ^ Number.MIN_VALUE)) : y), Math.fround((Math.sign((Math.min(x, Math.fround((Math.atan(x) >>> y))) >>> 0)) / x)))); }); testMathyFunction(mathy0, [-1/0, 0x100000000, 1.7976931348623157e308, 1/0, -0x100000000, -Number.MAX_VALUE, 2**53+2, 42, Number.MIN_VALUE, 0x07fffffff, 0x100000001, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -0x080000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -0, 2**53, 0, 1, 0x0ffffffff, 0.000000000000001, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=709; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; disableSPSProfiling(); } void 0; }");
/*fuzzSeed-209835301*/count=710; tryItOut("function g1.f2(o2) \"use asm\";   var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return ((-((((((Uint32ArrayView[1])) | ((-0x8000000)*0xec76c)) % (~(((0x350a16a7) < (0x34d26ac8))+(i1))))>>>(((0x0)))))))|0;\n  }\n  return f;");
/*fuzzSeed-209835301*/count=711; tryItOut("for(let x in x !== Math.min(/$(?:.)\\b{4,}?(?=(\\cQ))|.|\\xeB{1}^+{1}/i, b) /= -21) /*infloop*/L:do /*RXUB*/var r = /(((?![^]^)|(?:\u008d{3})|(?=\\B))[^]+?)|\\1/yi; var s = \"\\ufff1\"; print(s.match(r));  while(((x = Proxy.createFunction(({/*TOODEEP*/})( /x/g ), (x, x = [1,,], w, x = /(?:[^])|(?=\\3)((?![^]{3,7}))|.\\B.+|(?=[^])**(?:\\D|(?=[\\V\\v-\\x5B\\d])).{3}{4}/y, x, x = -1257392515, e, c, eval, y, x = undefined, d, x, x, b, b, x = \"\\u105A\", c, z, x, y, x, x =  /x/ , x, x, x, a, x, NaN, z, x = window, x, NaN, NaN, z, z, x, this.x, w, x, c = \"\\uCF44\", this.x, e, b, x = false, NaN, e, x, eval = y, c, x =  '' , x, z, x, z, x, x, z, y, c = y, x, \u3056 =  '' , x, x, eval, x = false, x, window, x, NaN, (function ([y]) { })(), eval, d =  \"\" , c, c, c, b = [[]], x, x, a, window, c, x = /\\1/gyi, b, d, x, w, x, a, x, x = new RegExp(\"(\\\\D|^|(?!\\\\u5c1D)+?)\\\\B\", \"i\"), x = \"\\u6D5E\", x, window = /\\b?/gym, window = z, x) =>  { \"use strict\"; yield  \"\"  } )) >= x|=\"\\uF601\" ? (4277) : ([this])));");
/*fuzzSeed-209835301*/count=712; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=713; tryItOut("/*iii*//*RXUB*/var r = /\\2$t\\S|[^]*+(?!(?!\\d)|\\1$|\\b|\\B+?)*?+?/gyi; var s = \"\\ub26c\\n\\nT\\ub26c\\n\\nT\"; print(r.exec(s)); /*hhh*/function yugbxp(x, ...d){v0 = evaluate(\"\\\"use strict\\\"; do {var v2 = t2.byteOffset; } while(( \\\"\\\" ) && 0);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (makeFinalizeObserver('tenured')).yoyo(arguments.callee.caller.caller.arguments), noScriptRval: false, sourceIsLazy: (x % 4 == 0), catchTermination: false }));}");
/*fuzzSeed-209835301*/count=714; tryItOut("/*RXUB*/var r = r0; var s = --arguments.callee.caller.caller.arguments; print(s.search(r)); /*RXUB*/var r = new RegExp(\"(?!(?!\\\\D?){1,2}|(\\\\cW))\", \"gy\"); var s = \"2\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=715; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.atan2(Math.imul(( ! (Math.atan2((x >>> 0), Math.fround(-Number.MAX_VALUE)) >>> 0)), 1/0), ( + Math.log2(( + Math.atan2(((-0x07fffffff | 0) > y), y))))) % (Math.atan2((mathy0(( ~ (0x080000001 | 0)), mathy2(y, y)) >>> 0), ((( + (0x080000000 * ( + x))) && mathy0(-0, y)) >>> 0)) >>> 0)) <= (Math.atan2((Math.pow(x, Math.fround((( ! 0x0ffffffff) === (x >>> 0)))) >>> 0), (Math.pow(Math.hypot(( - ( ~ Math.hypot(( + y), ( + y)))), (Math.clz32((x >>> 0)) >>> 0)), ( - -0x080000001)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-209835301*/count=716; tryItOut("\"use strict\"; m2.has(o0.b1);");
/*fuzzSeed-209835301*/count=717; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0, 0x07fffffff, 0x100000000, -0x100000000, -0x080000001, -(2**53+2), -0x07fffffff, -Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), -1/0, Math.PI, 2**53-2, 0x100000001, 1.7976931348623157e308, 0x080000001, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 2**53+2, 42, 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=718; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -36028797018963970.0;\n    i0 = ((d1) > (-33554433.0));\n    return (((i0)-(0x16e3ecb2)))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var axvlen = ( '' ); (RegExp.prototype.toString)(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=719; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[NaN, function(){}, NaN, NaN, NaN, NaN, NaN, NaN, {x:3}, function(){}, {x:3}, {x:3}, function(){}, function(){}]); ");
/*fuzzSeed-209835301*/count=720; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\1)\", \"yi\"); var s = \"\\u0017\"; print(s.search(r)); ");
/*fuzzSeed-209835301*/count=721; tryItOut("\"use strict\"; v0 = g2.eval(\"function g1.f0(m0) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var d2 = 4.835703278458517e+24;\\n    d1 = (d1);\\n    d1 = (-536870913.0);\\n    return ((((((abs((((0xd6c07f2e)+(0xf8d85645)+(0xffffffff)) << ((0x7b2537ce)+(i0))))|0)))>>>((!(0xb900f416))*0x96642)) % (0xffffffff)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-209835301*/count=722; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.abs(( + (( + ((mathy0((x >>> 0), ((Math.fround((y << 1)) >> (Math.fround(x) >> (( + Math.max(( + -1/0), -(2**53-2))) >>> 0))) >>> 0)) >>> 0) && (((-1/0 >>> 0) < ( + x)) >>> 0))) ? ( + Math.fround(Math.hypot(Math.fround(x), Math.fround(( + x))))) : ( + ( + Math.imul(( + ( + (( + (( ~ (y >>> 0)) | 0)) < ( + x)))), ( + -Number.MAX_VALUE))))))); }); testMathyFunction(mathy3, [-(2**53-2), 42, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, 0x080000000, -0x080000000, Number.MAX_VALUE, 0x080000001, 0, 0.000000000000001, 2**53, -0x07fffffff, -0, -Number.MIN_VALUE, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, 2**53-2, -0x100000001, -0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=723; tryItOut("\"use strict\"; while((-18) && 0)with({a:  /x/g })h2 = g1.t2[14];");
/*fuzzSeed-209835301*/count=724; tryItOut("\"use strict\"; for (var v of i2) { try { g0.g0.offThreadCompileScript(\"/*bLoop*/for (let eamjvm = 0; eamjvm < 68; ++eamjvm) { if (eamjvm % 2 == 0) { e1.has(this.a2); } else { /*oLoop*/for (var omfqsv = 0; omfqsv < 100; ++omfqsv) { e0.__proto__ = g0; }  }  } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 12 == 0), catchTermination: false })); } catch(e0) { } try { for (var p in b2) { try { e0.has(o2.a0); } catch(e0) { } try { a1.splice((String.raw.prototype), h0, f0); } catch(e1) { } try { v1.toString = (function() { try { s2 += 'x'; } catch(e0) { } print(uneval(v0)); return p1; }); } catch(e2) { } print(o0); } } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(g0.s1, g0.p2); }");
/*fuzzSeed-209835301*/count=725; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.hypot(( + ( + ( + ((y << ( + ( ! Math.ceil(( + x))))) / (((( - ( + y)) | 0) !== (x | 0)) | 0))))), (((x % y) * ( + (Math.fround(( ~ 42)) == (((Math.min(( + ( ! y)), ( + Number.MAX_VALUE)) >>> 0) * (x >>> 0)) | 0)))) > (Math.sqrt(Math.fround((( + -0) >>> 0))) >>> 0)))); }); testMathyFunction(mathy0, [42, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53-2), -Number.MIN_VALUE, -(2**53), -0x100000000, 1.7976931348623157e308, -1/0, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, 0, 2**53-2, 0.000000000000001, -0x07fffffff, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 0x100000001, 2**53+2, 0x100000000, 0x080000001, Number.MIN_VALUE, -0x080000001, -(2**53+2), -0x080000000, -0, Number.MIN_SAFE_INTEGER, 1, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=726; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.min(Math.min((Math.asin(Math.sinh(y)) >>> 0), (Math.fround(Math.atan2(x, (( ! ((x * (y | 0)) >>> 0)) >>> 0))) << ( + x))), ((Math.atan2(((Math.sqrt(x) >>> 0) >>> 0), y) || Math.min(((( + Math.max(1, y)) && (( + -0x0ffffffff) >>> 0)) >>> 0), Math.pow(Math.imul(y, x), (Math.max(x, (x / ( + 0.000000000000001))) >>> 0)))) >>> 0)) > (Math.round(( + ((Math.ceil(Math.pow(y, x)) ? Math.round(Math.atan2(Number.MAX_SAFE_INTEGER, Math.pow(y, y))) : -0x080000000) | 0))) >= (( + Math.min(( + Math.max(( + -0x100000000), ( + Math.max(Math.fround(y), x)))), ( + ( ! Math.min(Math.tanh(2**53+2), Math.fround(-Number.MAX_VALUE)))))) | 0))); }); testMathyFunction(mathy0, [0x100000001, Number.MAX_VALUE, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, 0x080000000, -0x100000001, 0.000000000000001, -(2**53), 42, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, -0x080000001, -0x0ffffffff, Number.MIN_VALUE, Math.PI, 2**53-2, 0x100000000, -0x07fffffff, 0x080000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, 1.7976931348623157e308, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, 0/0]); ");
/*fuzzSeed-209835301*/count=727; tryItOut("s1 = new String;");
/*fuzzSeed-209835301*/count=728; tryItOut("\"use strict\"; t1[8];");
/*fuzzSeed-209835301*/count=729; tryItOut("\"use strict\"; v1 = Array.prototype.some.apply(a2, [function(y) { yield y; /*infloop*/L:for(let z; this; this) o0.v1 = t2.length;; yield y; }, v0, a2, t2, x]);");
/*fuzzSeed-209835301*/count=730; tryItOut("v0 = a2.length;");
/*fuzzSeed-209835301*/count=731; tryItOut("/*oLoop*/for (dwcfyv = 0; dwcfyv < 8; ++dwcfyv) { for(let z of /*FARR*/[, {},  \"\" ]) a0.push(v1, null); } ");
/*fuzzSeed-209835301*/count=732; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0, 0/0, 0x0ffffffff, -1/0, -0x100000001, Math.PI, 0x100000001, -0x07fffffff, -(2**53), 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 0, 42, 0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, 0x07fffffff, 1/0, -0x0ffffffff, 1, Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-209835301*/count=733; tryItOut(";");
/*fuzzSeed-209835301*/count=734; tryItOut("Object.defineProperty(this, \"o0.a0\", { configurable: false, enumerable: false,  get: function() {  return new Array; } });");
/*fuzzSeed-209835301*/count=735; tryItOut("const x, lxerxs;print(x);\nthis.v2.toSource = f1;\n");
/*fuzzSeed-209835301*/count=736; tryItOut("\"use strict\"; /*bLoop*/for (var xagyqx = 0; xagyqx < 95; ++xagyqx) { if (xagyqx % 3 == 0) { print(((function fibonacci(voqcqu) { v2 = evaluate(\"\\\"use strict\\\"; print(x);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 77 == 10), sourceIsLazy: (x % 23 != 9), catchTermination: false, element: o0, elementAttributeName: s0 }));; if (voqcqu <= 1) { ; return 1; } ; return fibonacci(voqcqu - 1) + fibonacci(voqcqu - 2);  })(0))); } else { print((let (e=eval) e).prototype); }  } ");
/*fuzzSeed-209835301*/count=737; tryItOut("mathy1 = (function(x, y) { return ( - ( ~ Math.min((Math.max(y, y) | 0), ( ! Math.fround(Math.min(( ! y), (mathy0((( ~ (y >>> 0)) >>> 0), 0/0) >>> 0))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 0x080000001, -(2**53-2), -1/0, 0x080000000, -0x100000001, 1, 42, 0x0ffffffff, 0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, 2**53, 1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53-2, -0, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, -0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0, -0x080000000]); ");
/*fuzzSeed-209835301*/count=738; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ~ Math.ceil(Math.atan2(( + mathy1(( + ( - x)), ( + ( - y)))), (( ~ ((((((x >>> 0) > Math.max(x, x)) >>> 0) | 0) ? (0 | 0) : ((Math.exp((-Number.MAX_SAFE_INTEGER | 0)) | 0) | 0)) | 0)) >>> 0))))); }); testMathyFunction(mathy3, [-(2**53), -0x07fffffff, -(2**53-2), -(2**53+2), Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 0.000000000000001, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0x100000000, Math.PI, -0, -0x100000001, 0x100000001, -0x100000000, 0x0ffffffff, 1, -1/0, 0, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 42, 2**53, -0x080000001, 2**53-2, -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=739; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + Math.expm1(((( + ( ! (Math.sinh(( + ( + Math.imul(Math.fround(y), y)))) | 0))) >>> 0) | 0))), ( + Math.fround((( ~ (Math.fround((y | ( + x))) - x)) >>> 0))))); }); testMathyFunction(mathy0, [42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 2**53+2, -0x100000001, -(2**53-2), Math.PI, 2**53, Number.MAX_VALUE, 2**53-2, 0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, 1.7976931348623157e308, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, -0x080000001, -0, -1/0, 0x080000000, 0x080000001, -Number.MAX_VALUE, 0x100000000, Number.MIN_VALUE, 1, -0x080000000, 0/0, -(2**53), 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=740; tryItOut("\"use strict\"; (Function.prototype.call).bind\nArray.prototype.sort.apply(a2, [(function() { for (var j=0;j<32;++j) { f2(j%3==1); } })]);\n");
/*fuzzSeed-209835301*/count=741; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=742; tryItOut("/*hhh*/function eqdqic(){a0[ /x/g ];}/*iii*/var o0.v1 = a1.length;");
/*fuzzSeed-209835301*/count=743; tryItOut("print(uneval(i0));");
/*fuzzSeed-209835301*/count=744; tryItOut("\"use strict\"; v0 = g1.runOffThreadScript();v0 = (m1 instanceof p1);x = (4277);");
/*fuzzSeed-209835301*/count=745; tryItOut("print(x);\nm2 + '';\n");
/*fuzzSeed-209835301*/count=746; tryItOut("a1 = Array.prototype.filter.call(g2.a1, (function() { Object.defineProperty(this, \"a2\", { configurable: ( /* Comment */[,]) &= [1,,], enumerable: /*FARR*/[6].filter(Math.asinh),  get: function() {  return Array.prototype.slice.call(a0, NaN, NaN, s0, e1, m1, h1); } }); return g1.i0; }));");
/*fuzzSeed-209835301*/count=747; tryItOut("a0.unshift(v0);");
/*fuzzSeed-209835301*/count=748; tryItOut("m0.delete(g0);");
/*fuzzSeed-209835301*/count=749; tryItOut("{ void 0; void gc(); } h1 = g1;");
/*fuzzSeed-209835301*/count=750; tryItOut("mathy1 = (function(x, y) { return Math.max(Math.pow(( + Math.atan2(-0x080000000, y)), ((mathy0(x, 2**53-2) >>> Math.atan2(mathy0(y, x), ( + Math.fround((( + (x % y)) == -0x100000000))))) >>> 0)), ((Math.trunc(((Math.hypot(y, x) ? ( + y) : (( + ( + ( + ( - ( + y))))) >>> 0)) | 0)) - ( + (Math.fround(( ~ ( + (( ~ (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))) ** (y | 0)))) | 0)); }); testMathyFunction(mathy1, [0x100000001, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), 0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, 0.000000000000001, 1/0, 0x080000001, 1, 2**53, -0x080000001, -0x100000001, -0, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -1/0, -0x07fffffff, 0/0, 2**53-2, 0, 2**53+2, 0x07fffffff, -0x080000000, -0x100000000, -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-209835301*/count=751; tryItOut("o1.g2.e2.delete(new (x)().unwatch(\"7\"));");
/*fuzzSeed-209835301*/count=752; tryItOut("/*RXUB*/var r = /((?=\\3)*){0,}/yi; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=753; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sqrt(( + (Math.fround(Math.round(Math.fround(( + 0x07fffffff)))) + Math.fround(Math.sin(Math.fround(2**53-2)))))); }); testMathyFunction(mathy1, /*MARR*/[new String(''), new String(''), new Boolean(false)]); ");
/*fuzzSeed-209835301*/count=754; tryItOut("/*tLoop*/for (let d of /*MARR*/[-Number.MAX_SAFE_INTEGER, new Boolean(true), -Number.MAX_SAFE_INTEGER, new Boolean(true), 1.2e3, new Boolean(true), [1], new Boolean(true), -Number.MAX_SAFE_INTEGER, new Boolean(true), 1.2e3, 1.2e3, new Boolean(true), [1], new Boolean(true), 1.2e3, new Boolean(true), new Boolean(true), [1]]) { a0.pop(); }");
/*fuzzSeed-209835301*/count=755; tryItOut("for (var p in a0) { try { f0(s2); } catch(e0) { } try { t1 = new Float32Array(t0); } catch(e1) { } Array.prototype.pop.call(o0.a2, Math.atan2(-24, /(\\B(?!\\1)|\\d(?!(?=(?=.))))/gyi), g2.b1, i1); }");
/*fuzzSeed-209835301*/count=756; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(Math.pow((( ~ (mathy1(( + ((Math.exp(x) >>> 0) & 0)), ( ~ y)) | 0)) | 0), ( + Math.atan((( + Math.cbrt(Math.atan2(( + x), ( + x)))) >= Math.expm1(y)))))) << Math.fround((((Math.fround(( ! mathy0((( - y) | 0), 0))) , Math.fround(Math.log2(Math.fround(x)))) | ( ~ (Math.max((( + (Math.tanh(-Number.MAX_SAFE_INTEGER) | 0)) | 0), (y | 0)) | 0))) >>> 0))); }); ");
/*fuzzSeed-209835301*/count=757; tryItOut("s2 += s1;");
/*fuzzSeed-209835301*/count=758; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.sign(mathy2(Math.tanh((mathy2(Number.MAX_VALUE, 0x100000001) ? y : y)), Math.fround(( ~ Math.fround((((mathy1(x, x) | 0) , (y | 0)) | 0))))))); }); testMathyFunction(mathy3, [0x07fffffff, -(2**53-2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, 0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, -0x080000000, 0x0ffffffff, 2**53, Number.MIN_VALUE, 1, 0/0, -0x07fffffff, 42, 0.000000000000001, -0x100000000, 2**53+2, 1/0, Number.MAX_VALUE, 0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 2**53-2, -0, 0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=759; tryItOut("/*MXX2*/g1.Math.floor = a1;");
/*fuzzSeed-209835301*/count=760; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.log1p(( + ( ~ ( + Math.pow((((Math.asin(Math.pow((42 | y), (-0x0ffffffff > x))) >>> 0) !== (( + Math.sin(( + y))) >>> 0)) >>> 0), Math.imul((Math.sin(1.7976931348623157e308) | 0), Math.fround((x === Math.fround(x)))))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x080000000, -0, -0x100000001, Number.MIN_VALUE, 0, Number.MAX_VALUE, 1, 0/0, -(2**53-2), 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0x100000000, 0x080000000, 2**53+2, -0x080000001, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 42, 0x080000001, 0x100000000, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), -1/0]); ");
/*fuzzSeed-209835301*/count=761; tryItOut("testMathyFunction(mathy2, [-(2**53-2), 1.7976931348623157e308, -1/0, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 2**53+2, 2**53-2, 1, 42, 0x080000000, -0x100000001, 0, -0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, -0, -0x080000001, 0x07fffffff, 2**53, 0x100000001, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, -(2**53)]); ");
/*fuzzSeed-209835301*/count=762; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((((Math.acosh(Math.fround(( ~ (((( ~ y) >>> 0) << -0x0ffffffff) >>> 0)))) ? mathy1((y == 0/0), Math.log2(Math.atan2(-0x0ffffffff, x))) : Math.hypot((((Math.atan2(x, x) | 0) ? Math.fround(Math.acos((Math.atan2((y >>> 0), ( + x)) >>> 0))) : ((( ! x) >>> 0) | 0)) | 0), y)) >>> 0) , (Math.round(( + Math.atan2(( + Math.hypot((mathy0((2**53+2 >>> 0), (((x & 2**53+2) ? Math.fround(x) : Math.fround(y)) | 0)) >>> 0), ((y | 0) >> Math.fround(Math.log10(Math.fround(x)))))), ( + x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [2**53, -(2**53-2), 0x100000000, -1/0, Number.MIN_VALUE, -0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, 42, -0x07fffffff, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 0x100000001, -0, -0x100000001, -(2**53), 0x07fffffff, 0/0, 1.7976931348623157e308, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=763; tryItOut("\"use strict\"; v0 = evalcx(\"v0 = o2.r0.exec;\", g0);");
/*fuzzSeed-209835301*/count=764; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.pow(( + Math.pow(( + (( + (Math.fround(( + (y >>> 0))) ? Math.imul(Math.fround((Math.fround(-0x07fffffff) > Math.fround(x))), y) : Math.fround((0x080000000 >= Math.fround(x))))) && ( + ( ~ ((Math.fround(y) ? (0x0ffffffff >>> 0) : ((Math.imul((y >>> 0), y) >>> 0) >>> 0)) >>> 0))))), (Math.abs((((((Math.fround(y) && (( + x) | 0)) | 0) ** (( + y) | 0)) | 0) | 0)) | 0))), Math.tan(Math.max(Math.fround(x), x)))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, Math.PI, 1, -0x100000001, 0x080000000, 0.000000000000001, -0, 1/0, -(2**53), 2**53-2, 0x07fffffff, -0x080000001, 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 2**53+2, 0x100000001, 42, 0/0, -Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -Number.MIN_VALUE, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-209835301*/count=765; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( + Math.max((( ! (((( + ((x - x) | 0)) | 0) ? ((( + y) & (y >>> 0)) >>> 0) : Math.fround((y * x))) >>> 0)) === (((-(2**53) >>> 0) >>> (( ~ y) >>> 0)) >>> 0)), ((mathy0(y, (0x080000000 >>> 0)) == x) | 0)))); }); ");
/*fuzzSeed-209835301*/count=766; tryItOut("mathy3 = (function(x, y) { return Math.asinh(Math.fround((( + ( + Math.log2(( + ( + Math.atan(( + Math.log1p(( + 2**53+2))))))))) && Math.atan(mathy0((mathy2(x, y) >>> 0), (((0 | 0) <= 1/0) | 0)))))); }); ");
/*fuzzSeed-209835301*/count=767; tryItOut("print((4277));a = 20;");
/*fuzzSeed-209835301*/count=768; tryItOut("selectforgc(o0);");
/*fuzzSeed-209835301*/count=769; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.imul((( + (mathy4(Math.atan(((Math.sqrt(x) | 0) | 0)), (( + x) && y)) <= ( + Math.log2(x)))) || mathy4((( - ((Math.cosh(( + x)) | 0) >>> 0)) >>> 0), (( + (( + x) ^ ( + y))) >>> 0))), ( + ((mathy0(Math.fround(Math.hypot(Math.fround(-0x100000001), Math.fround(( + (y , mathy2(Math.atan(Number.MAX_SAFE_INTEGER), (( ! x) >>> 0))))))), ( + ((Math.pow((( + (42 & x)) | 0), (y | 0)) | 0) , x))) >>> 0) * (((Math.min(y, 0x080000000) | 0) !== Math.min(Math.pow(Math.fround(Math.atan2(Math.fround(0x080000000), Math.fround(0/0))), (( ! y) | 0)), (x | 0))) >>> 0)))); }); testMathyFunction(mathy5, [0x080000001, -0x080000000, 1, Math.PI, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0, -Number.MAX_VALUE, 2**53, 0x080000000, 1.7976931348623157e308, 0/0, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 42, 2**53-2, 0.000000000000001, -0, 2**53+2, -(2**53-2), -0x100000001, Number.MAX_VALUE, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=770; tryItOut("mathy4 = (function(x, y) { return (( - (( - Math.max(x, x)) ? Math.imul(( + y), (x + x)) : ( + Math.fround(Math.max(Math.fround(y), Math.fround((-0x0ffffffff + Math.fround(Math.sin((0.000000000000001 | 0)))))))))) + ( + Math.max(Math.fround(mathy3(Math.fround(( + Math.fround(Math.sin(y)))), (y | 0))), ( + Math.max(Math.fround(( + Math.sin(Math.log((Math.fround(-0) >>> 0))))), 2**53+2))))); }); ");
/*fuzzSeed-209835301*/count=771; tryItOut("\"use strict\"; /*vLoop*/for (vqnfof = 0; vqnfof < 68; ++vqnfof) { const e = vqnfof; v1 = g0.runOffThreadScript(); } ");
/*fuzzSeed-209835301*/count=772; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=773; tryItOut("e2 = x;function this.NaN(b, (4277))argumentsthis.v2 = (this.i0 instanceof e2);");
/*fuzzSeed-209835301*/count=774; tryItOut("\"use strict\"; e2.delete(this.t2);");
/*fuzzSeed-209835301*/count=775; tryItOut("window = (({/*TOODEEP*/})(window)), z = (this.__defineSetter__(\"x\", decodeURI)), x = 'fafafa'.replace(/a/g, decodeURI), eval, e, x, jbmtbh, d, wffuuy, x;v1 = a1.length;");
/*fuzzSeed-209835301*/count=776; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.min(Math.fround((mathy2(((Math.imul((Math.trunc(Math.ceil((mathy2((-0x080000000 >>> 0), (y >>> 0)) >>> 0))) | 0), (( - y) | 0)) | 0) >>> 0), (Math.log10(Math.acosh(Math.fround(( + Math.fround(Math.fround(Math.imul(( + -0x07fffffff), y))))))) >>> 0)) >>> 0)), Math.fround(( + Math.imul(Math.fround((mathy2(Math.atan2((Math.imul((y >>> 0), (y >>> 0)) >>> 0), x), (( - x) | 0)) >>> 0)), Math.fround(( + Math.pow(y, ((y < x) * (-(2**53-2) ^ x)))))))))); }); testMathyFunction(mathy3, [1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, -0x100000000, 42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, 0x100000000, 0x07fffffff, 0, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 0x080000001, -(2**53), -(2**53-2), -0x0ffffffff, 1/0, 0/0, Math.PI, 2**53-2, 0.000000000000001, -(2**53+2), 2**53+2, -0x080000001, 1, -Number.MAX_SAFE_INTEGER, -0, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=777; tryItOut("for (var p in m0) { t0.toSource = (function() { a2 + h0; return o1.a1; }); }");
/*fuzzSeed-209835301*/count=778; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot(Math.fround(( + Math.asin(( + (( + ( - y)) && ( + Math.tan(( + ( + Math.acosh(( + x))))))))))), Math.fround(Math.fround(((( + (Math.imul(Math.hypot(mathy3(x, x), mathy3(x, x)), y) >>> 0)) >>> 0) !== (Math.atan2((Math.atan2(Math.fround((Math.sin(y) | 0)), Math.fround(-(2**53+2))) >>> 0), (( + Math.log10(((( + x) === (((0x07fffffff | 0) == y) | 0)) | 0))) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-209835301*/count=779; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.acos((( ! Math.fround(((mathy0(x, Math.fround(( + Math.clz32(y)))) >>> 0) * ((Math.asinh(0/0) || (y | 0)) >>> 0)))) | 0)) | 0) !== (Math.imul(((( ! ((x == ((y ** y) % (( ! Math.fround(1)) >>> 0))) >>> 0)) >>> 0) | 0), (( + mathy4(( + 0x080000000), ( + ( - y)))) | 0)) | 0)); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x100000001, 0x080000000, 2**53+2, 42, Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -0x100000000, -(2**53), 0x07fffffff, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, 1, -1/0, -0x080000001, Number.MIN_VALUE, -(2**53+2), -0x07fffffff, 2**53, -0x080000000, Number.MAX_VALUE, 0/0, 0, 1.7976931348623157e308, 0x0ffffffff, -(2**53-2), 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, -0x0ffffffff, 0x080000001]); ");
/*fuzzSeed-209835301*/count=780; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=781; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=782; tryItOut("mathy1 = (function(x, y) { return (Math.imul(Math.fround(( - Math.fround(Math.fround(( ~ ( + Math.tanh(y))))))), ( + (( + (Math.asinh(((Math.atan2((x >>> 0), (y | 0)) | 0) | 0)) | 0)) <= ( + Math.fround(Math.tan(( + (2**53+2 >>> (x ? ( + y) : ( + x)))))))))) >> Math.max((mathy0(0/0, ( + x)) | 0), (Math.atan2((Math.hypot((( ~ Math.fround(Math.atan2(x, Math.fround(y)))) | 0), (Math.fround(Math.atan(Math.fround(x))) | 0)) | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0))); }); testMathyFunction(mathy1, [0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 1, 42, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 1/0, -0x07fffffff, -0, -1/0, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, Math.PI, -(2**53-2), -0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, 2**53, 2**53+2, 0, 0.000000000000001, -(2**53), 0x100000000, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=783; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul((( + ( + Math.tanh(( + Math.min((((y | 0) << (x | 0)) | 0), (x | 0)))))) < ((y ? x : Math.max(Math.atan(( + Math.imul((y >>> 0), y))), ( + ( - (Number.MIN_VALUE >>> 0))))) >>> 0)), (Math.hypot(Math.fround((Math.imul(((x ? y : ( + ( + y))) >>> 0), x) >>> 0)), Math.fround(( ! Math.abs(x)))) ? Math.fround(mathy0(Math.fround(Math.acosh(( + x))), Math.fround(Math.fround(Math.tanh(Math.fround(x)))))) : (( + (Math.min(y, Math.fround(Math.abs(Math.fround(Math.pow(2**53+2, Number.MAX_SAFE_INTEGER))))) | (x >>> 0))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, eval(\"-9\", length), eval(\"-9\", length), eval(\"-9\", length), eval(\"-9\", length), 1.3, eval(\"-9\", length), eval(\"-9\", length), 1.3, 1.3, eval(\"-9\", length), eval(\"-9\", length), eval(\"-9\", length), 1.3, eval(\"-9\", length), eval(\"-9\", length), eval(\"-9\", length), 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, eval(\"-9\", length), 1.3, eval(\"-9\", length), eval(\"-9\", length), 1.3, 1.3, 1.3, 1.3]); ");
/*fuzzSeed-209835301*/count=784; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=785; tryItOut("mathy2 = (function(x, y) { return ( - (Math.min(((Math.fround(( - ((Math.abs(y) >>> 0) | 0))) + Math.max(Math.fround((42 ^ (y + y))), mathy0(( + ( + ( + y))), Math.sqrt((((x | 0) > 0x080000001) | 0))))) >>> 0), (( + (( + Math.cosh(Number.MAX_SAFE_INTEGER)) ? ( + Math.min((y >>> 0), (Math.max(Math.sin(y), ( ~ y)) >>> 0))) : ((Math.max((x >>> 0), ((x && y) | 0)) | 0) ? ( + x) : ( + Math.cosh(y))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 1, 0/0, -(2**53+2), -0, 2**53, -Number.MIN_VALUE, 0x100000000, 0, 0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -0x100000000, -0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, 2**53+2, 2**53-2, -0x0ffffffff, -0x080000000, -(2**53-2), Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, -1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-209835301*/count=786; tryItOut("/*infloop*/while(((z = true))){{ if (isAsmJSCompilationAvailable()) { void 0; gcslice(6543); } void 0; } /*MXX1*/o1.o2 = g1.RegExp.$+;L: /* no regression tests found */ }");
/*fuzzSeed-209835301*/count=787; tryItOut("\"use strict\"; s0 = ''\nlet(x, w = window, oovjob, c, \u3056, fkyjtc, z) ((function(){yield null;})());let(w = timeout(1800), \u3056 = true) { with({}) ([[]]);}");
/*fuzzSeed-209835301*/count=788; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return ( ~ (( ! mathy0(Math.atan(((( + x) ^ (-0x100000001 >>> 0)) >>> 0)), ( - y))) >>> 0)); }); testMathyFunction(mathy3, [0x0ffffffff, -0, 42, -0x100000000, 1/0, -0x100000001, 2**53, 0x080000000, -1/0, Number.MAX_VALUE, -0x0ffffffff, -0x080000001, 0/0, 1.7976931348623157e308, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, -(2**53), 0, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, -Number.MIN_VALUE, 2**53-2, -(2**53+2), -0x080000000, 1, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-209835301*/count=789; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2((( - Math.fround(( - Math.fround(y)))) >>> 0), (Math.fround(( + Math.fround(( + Math.round(( + Number.MIN_SAFE_INTEGER)))))) >>> 0)) | 0); }); testMathyFunction(mathy3, [-0x080000000, 42, Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, -0x07fffffff, 0/0, 1, 2**53-2, -(2**53-2), 2**53, 0x100000000, 1.7976931348623157e308, 0x080000000, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, -1/0, 0, -Number.MAX_VALUE, 2**53+2, -0x100000001, -0x080000001, -Number.MIN_VALUE, -0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-209835301*/count=790; tryItOut("\"use strict\"; v1 = o2.g2.runOffThreadScript();");
/*fuzzSeed-209835301*/count=791; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-209835301*/count=792; tryItOut("var nixsnv = new ArrayBuffer(12); var nixsnv_0 = new Float64Array(nixsnv); nixsnv_0[0] = 1; (this.__defineGetter__(\"d\", Float64Array));Array.prototype.forEach.call(a1, (function() { v1 = Object.prototype.isPrototypeOf.call(g1.f1, b2); return i0; }));this.a2 = g2.r1.exec(s1);function b(c, nixsnv_0[7], ...nixsnv)\"\\uF366\" ? \"\\u3591\" : \"\\u4E4B\"print(nixsnv_0[0]);L:with(\"\\u7030\"){h1 + e2; }print(nixsnv_0);");
/*fuzzSeed-209835301*/count=793; tryItOut("f1 + '';");
/*fuzzSeed-209835301*/count=794; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-209835301*/count=795; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((Math.hypot((((((Math.PI << y) | 0) ^ (Math.sin(x) | 0)) | 0) | 0), (( + ( ! Math.imul(0x080000001, (Math.fround(( ! Math.trunc(( + Number.MIN_SAFE_INTEGER)))) >>> 0)))) | 0)) | 0) > ( + (( + Math.cosh((Math.cbrt(((1 ? 0x07fffffff : x) >> Math.fround(x))) >>> 0))) ? ( + ((Math.fround(Math.min((x | 0), x)) >>> 0) ? mathy2(((((mathy1((x | 0), (/*iii*/a0.forEach((function(j) { f1(j); }));/*hhh*/function jovpak(this, c = new RegExp(\"(?=\\\\b)+?\", \"gi\"), x, w, y, x, \u3056, x = \"\\u03BE\", eval, y, y, x, eval, x, let, w, yield, y, x, x, window, y, x, w, c = -1, this.w, x, x, z, a, y = -12, x, \u3056, y = -1, y, a, x, y, y, window = 11, e, z, e, c, NaN, x, y, y = false, \u3056 =  /x/g , z, x, window, y, c =  '' , NaN, x = b){(\"\\uE27A\");} | 0)) | 0) | 0) || (-(2**53-2) | 0)) | 0), mathy0((y >>> 0), y)) : Math.atan2(( + Math.imul(( + (Math.sin(x) >>> 0)), Math.fround(x))), ((y >>> 0) ? ((x >= -Number.MIN_VALUE) >>> 0) : x)))) : ( + (mathy0((Math.max(Math.max(((Math.atan2((x | 0), y) | 0) | 0), ((-(2**53) - ((Math.log10((x >>> 0)) | 0) | 0)) | 0)), mathy0((Math.exp((x | 0)) | 0), x)) | 0), (Math.pow(-Number.MIN_VALUE, Math.fround(Math.atanh((y | 0)))) | 0)) | 0))))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -(2**53-2), 0x100000001, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 0, -0x0ffffffff, 2**53, -Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, Math.PI, 1/0, 0/0, Number.MIN_SAFE_INTEGER, 0x080000000, 0x080000001, -0, 2**53+2, 42, -1/0, Number.MIN_VALUE, -0x080000001, -0x100000001, 2**53-2, -(2**53), -0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=796; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=797; tryItOut("\"use strict\"; /*vLoop*/for (vbiart = 0; vbiart < 9; ++vbiart) { d = vbiart; print(d); } ");
/*fuzzSeed-209835301*/count=798; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var log = stdlib.Math.log;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -35184372088833.0;\n    i1 = ((0x56ebf23d));\n    {\n      {\n        i2 = (i0);\n      }\n    }\n    (Int8ArrayView[(-(i2)) >> 0]) = ((i2)-(!(i1)));\n    d3 = (d3);\n    d3 = (+/*FFI*/ff(((((i0)) & ((i1)+((Infinity) == (((((-257.0)) * ((72057594037927940.0)))) / ((Float64ArrayView[4096]))))+(i2))))));\n    /*FFI*/ff(((timeout(1800))), ((-((-((Infinity)))))), ((((((0xffffffff))>>>((0xfb46d708))) % (0xc4b69fb5)) | (-0xdbc4e*(0xffffffff)))), ((+(0xffffffff))));\n    i1 = (i0);\n    (Uint16ArrayView[(-0x8eb9*((((0xfb3d7ea6))>>>((0xfdd5092a)-(-0x8000000))) <= (((0xe5dcfbbb)-(0xa4cd17f6))>>>(((0x5ef7b90e) >= (0x7fffffff)))))) >> 1]) = ((i0)+((i1) ? ((0xf49b6709)) : (i1))-(((0xffffffff) ? ((0x21240754) >= (0x0)) : (i0)) ? (i1) : (i0)));\n    d3 = ((\n({a2:z2}) >>>=  '' ));\n    i0 = ((((d3)) / ((+abs((((((65537.0) + (-590295810358705700000.0))) % ((d3)))))))) != (-524287.0));\n    i2 = (/*FFI*/ff(((~~(d3))), ((((-8589934593.0)) % ((Float64ArrayView[(((32.0)) / (((0x7dd35f15)) ^ ((0x7d33c630)))) >> 3])))), ((((0x6456b414) ? (+(-1.0/0.0)) : (8589934591.0)) + (Infinity))), ((Infinity)), ((~~(+(0x6622d5d6)))), ((abs((abs((abs((((0xb33bf0b8))|0))|0))|0))|0)), ((((0x766f3002)+(0x76acf9f5)) ^ ((0x5d0d8df5) / (0x38d8470e)))), ((NaN)))|0);\n    i0 = ((((i1))>>>(-(((0xad1d8*(i1)) >> ((i1)-(i2))) <= (((return)) << ((i0)))))));\n    {\n      d3 = (+abs(((-1048577.0))));\n    }\n    return +((((+/*FFI*/ff(((((((0x3e2a7*(i1)) | ((0x636bd2c9)-(0x491a2b8b)-(-0x8000000))))) & ((-0x8000000)-((((0xd14e3723)) << ((0xfbe10001))) < (((0xf677bc44)) ^ ((0xffffffff))))+(0x463ba20d)))), ((((-9223372036854776000.0)) * ((+/*FFI*/ff(((~~(65.0))), ((+log(((3.777893186295716e+22))))), ((549755813889.0))))))), (((((((0xfde94058)) | ((0xbfde7946))))-(i2)) ^ ((Uint8ArrayView[((0xffffffff)) >> 0])))), ((+(0.0/0.0))), ((4611686018427388000.0)), ((((0x6ba556c7)) & ((0xfb5d36d7)))), ((~((-0x8000000)))), ((-288230376151711740.0)), ((-9.44473296573929e+21)), ((274877906944.0))))) % ((+pow(((x)), ((+((((1.0625) != (4503599627370495.0))+(i2))>>>((!(i1))+((~((0xad602259)))))))))))));\n  }\n  return f; })(this, {ff: String.prototype.normalize}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000001, 0.000000000000001, -Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 2**53, -Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0, 0x080000001, -0x100000000, 42, 1/0, -0x100000001, 0x0ffffffff, -(2**53+2), -0x080000000, -0, 2**53+2, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 1, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=799; tryItOut("{ void 0; void schedulegc(this); }\nvar jegkny = new ArrayBuffer(4); var jegkny_0 = new Uint16Array(jegkny); print(jegkny_0[0]); jegkny_0[0] = -26; {}\n");
/*fuzzSeed-209835301*/count=800; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return ( + (( + ( + ( + (((Math.imul(Number.MAX_VALUE, (y >>> 0)) >>> 0) ** ( + Math.cbrt((((x | 0) - (Math.fround(( ! Math.fround(y))) | 0)) | 0)))) >>> 0)))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[function(){}, [1], [1], \"\\uF07D\", function(){}, [1], function(){}, function(){}, [1], \"\\uF07D\", [1], \"\\uF07D\", function(){}, [1], \"\\uF07D\", \"\\uF07D\", \"\\uF07D\", \"\\uF07D\", \"\\uF07D\", function(){}, [1], function(){}, function(){}, [1], function(){}, function(){}, [1], function(){}, [1], [1], function(){}, \"\\uF07D\", \"\\uF07D\", [1], \"\\uF07D\", [1], \"\\uF07D\", function(){}, function(){}, function(){}, \"\\uF07D\", [1], function(){}, function(){}, \"\\uF07D\", \"\\uF07D\", \"\\uF07D\", function(){}, \"\\uF07D\", [1], function(){}, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1]]); ");
/*fuzzSeed-209835301*/count=801; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.pow(Math.fround(Math.tan(Math.atan2((Math.fround(Math.atan(Math.fround(Math.round((y | 0))))) , Math.atan2(( + x), 0x080000001)), ( ~ (y >>> 0))))), Math.fround(Math.pow((Math.min(( + (Math.fround(x) == ( + -0x080000001))), ((( ~ ( - x)) >>> 0) | 0)) >>> 0), ( + mathy0(y, ( + ( ~ Math.fround(( ! y))))))))) | 0); }); ");
/*fuzzSeed-209835301*/count=802; tryItOut("\"use asm\"; L:for(var d = x in  '' ) {let (z) { (d >= false); } }");
/*fuzzSeed-209835301*/count=803; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(( + Math.fround(( - Math.fround(mathy0(Math.fround((Math.sqrt((( ! ((0/0 / -Number.MAX_VALUE) | 0)) | 0)) | 0)), (( + ( ! (x >>> 0))) | 0)))))), ( + Object.defineProperty(y, \"prototype\", ({configurable: (x % 54 != 20), enumerable: (x % 14 != 2)})), (! /* Comment */(4277))))); }); testMathyFunction(mathy1, /*MARR*/[ '' , new Boolean(true), new Boolean(true),  '' ,  '' , function(){}, function(){}, function(){}, new Boolean(true), function(){},  '' , function(){}, function(){}]); ");
/*fuzzSeed-209835301*/count=804; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.cbrt(Math.fround(( + (Math.fround(Math.fround(Math.log1p(Math.fround((x != Math.fround(x)))))) + Math.fround(mathy0(( ! (Math.hypot(( + ( + Math.atan2(( + x), ( + x)))), (( + (( + -0x0ffffffff) !== ( + x))) >>> 0)) | 0)), Math.acos(y)))))))); }); testMathyFunction(mathy3, [-0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, -1/0, 0x080000000, -0x0ffffffff, 2**53-2, Number.MAX_VALUE, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -0x080000000, 42, -0, 2**53+2, -(2**53-2), -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, 1/0, -0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -0x080000001, 2**53, -(2**53), 1, Math.PI]); ");
/*fuzzSeed-209835301*/count=805; tryItOut("testMathyFunction(mathy5, [(new Number(-0)), objectEmulatingUndefined(), /0/, -0, (new Boolean(true)), NaN, [], false, [0], '', true, (new Number(0)), 0, '0', (function(){return 0;}), undefined, '\\0', 0.1, (new String('')), ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), 1, '/0/', (new Boolean(false)), null, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-209835301*/count=806; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((+log(((((+(imul((i2), ((((0x60686b5c) / (0x6f90039a))>>>(undefined))))|0)) > (((-1.5474250491067253e+26)) - ((Infinity)))))))));\n  }\n  return f; })(this, {ff: c => \"use asm\";   var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 65537.0;\n    var d3 = -7.737125245533627e+25;\n    d2 = (d2);\n    {\n      {\n        return (((0x85c4fb2a)+(!((((1)*0x43817)>>>((0x5dc0896d) / (0x747ff55e)))))-(0x7beddf52)))|0;\n      }\n    }\n    return (((Uint32ArrayView[2])))|0;\n  }\n  return f;}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=807; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(Math.fround(Math.pow(Math.fround(( + 0.000000000000001)), Math.min((-0x0ffffffff >>> 0), -Number.MIN_SAFE_INTEGER)))) + ( ! x)) ? ( + mathy0(((Math.fround(mathy0(x, ( - ( ~ Math.fround(-(2**53)))))) * (x >>> 0)) >>> 0), Math.min(y, x))) : (mathy0((x - 1), x) ? ( + (( + Math.asinh(( + Math.tan(Math.fround(Math.atan2((y >>> 0), ((x | 0) ** x))))))) >> ( + ((( + ( ~ ( + y))) | 0) >= Math.fround((Math.tan(Math.imul(2**53-2, Number.MIN_SAFE_INTEGER)) >>> 0)))))) : ((Math.pow(( ~ y), 0x0ffffffff) | 0) <= Math.fround((Math.fround(mathy0((0x0ffffffff >>> 0), (y >>> 0))) % Math.fround(Math.imul(mathy0(0, y), ((x | 0) >> Math.log2(0.000000000000001))))))))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(),  'A' , 0x20000000, objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , 0x20000000, 0x20000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' ,  'A' , 0x20000000,  'A' , objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(), 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, objectEmulatingUndefined(), 0x20000000, objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(),  'A' , 0x20000000,  'A' ,  'A' , 0x20000000, objectEmulatingUndefined(),  'A' ,  'A' , objectEmulatingUndefined(), 0x20000000,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(),  'A' ]); ");
/*fuzzSeed-209835301*/count=808; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return ( - (Math.min((Math.fround(Math.pow((Math.fround(Math.max(Math.fround(((( ~ Math.max(y, x)) | 0) & (Math.atan2(x, y) | 0))), Math.fround((( + Math.max(y, y)) ** -1/0)))) >>> 0), Math.fround(( + (( + (Math.fround(( + mathy0(( + y), ( + x)))) <= y)) ^ ( + y)))))) | 0), (Math.fround((Math.fround((x ? x : (( + x) >>> 0))) !== Math.fround(y))) | 0)) | 0)); }); testMathyFunction(mathy5, [Math.PI, Number.MAX_VALUE, 42, 0/0, 2**53+2, -Number.MIN_VALUE, -0x100000001, 2**53-2, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, 0x100000000, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, -0x080000001, -0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, 0x0ffffffff, 1.7976931348623157e308, -1/0, -0x07fffffff, 0x080000001, 1/0, -0x0ffffffff, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=809; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(mathy0(Math.fround(Math.log2(Math.sign(( + mathy0(x, ( + y)))))), Math.fround(Math.fround((( + mathy1(Math.atanh(((0 > Math.abs(y)) | 0)), 42)) * Math.fround((Math.fround(Math.atan2((Math.exp(Math.fround(Math.fround((Math.fround(x) * Math.fround(x))))) >>> 0), Math.fround(y))) | Math.fround(( + (-0x100000000 >>> 0)))))))))), ( + Math.acosh(((( + (Math.cosh(y) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -1/0, -0x07fffffff, 1, Number.MIN_VALUE, 0x0ffffffff, 42, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, 2**53, 0x07fffffff, -0, 0x100000000, -0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, Math.PI, 0.000000000000001, 0x080000000, 0, -(2**53+2), -0x080000001]); ");
/*fuzzSeed-209835301*/count=810; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min((( ! y) & Math.fround(Math.ceil(((y >= Math.abs(x)) | 0)))), Math.fround((Math.fround(Math.fround(Math.abs(Math.fround(Math.fround(( + Math.fround(1))))))) >> Math.fround(Math.fround(mathy0(Math.atanh(mathy0((( - y) ^ ( + y)), ( + ( ~ Math.fround(x))))), ( ~ -Number.MAX_VALUE))))))); }); ");
/*fuzzSeed-209835301*/count=811; tryItOut("i1 + a2;");
/*fuzzSeed-209835301*/count=812; tryItOut("\"use strict\"; /*infloop*/for(var b(x) in ((this.__defineSetter__(\"d\", Number.parseInt))(new Int32Array(((function sum_indexing(qzvakr, ajdfvk) { ; return qzvakr.length == ajdfvk ? 0 : qzvakr[ajdfvk] + sum_indexing(qzvakr, ajdfvk + 1); })(/*MARR*/[-Infinity, new Boolean(false)], 0)) >>>= (({w: -0}))))))this.h1.getPropertyDescriptor = f1;");
/*fuzzSeed-209835301*/count=813; tryItOut("g0.offThreadCompileScript(\"x\", ({ global: o2.g2, fileName: null, lineNumber: 42, isRunOnce: \"\\u8F4A\", noScriptRval: (x % 6 == 4), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-209835301*/count=814; tryItOut("\"use strict\"; o0.v2 = t1.length;");
/*fuzzSeed-209835301*/count=815; tryItOut("(new {}((4277)));{}");
/*fuzzSeed-209835301*/count=816; tryItOut("\"use strict\"; /*infloop*/for(var a = (void (let (e) window)); (void options('strict_mode')); eval(\"window\")) o0 + '';");
/*fuzzSeed-209835301*/count=817; tryItOut("/*infloop*/ for (var  /x/g .b of x)  for (var a of ((4277) ? \"\\u1AB4\"() : this)) {print(-15\n ? undefined <=  ''  : (uneval( /x/ ))); }");
/*fuzzSeed-209835301*/count=818; tryItOut("mathy4 = (function(x, y) { return (Math.exp(( + ( ~ (Math.hypot(( - x), Math.imul(Math.fround((Math.expm1(x) >>> 0)), ( - 0))) - Math.cosh(( + Math.min((( ~ (x | 0)) | 0), ( + Math.pow(x, (( ! (y >>> 0)) >>> 0)))))))))) | 0); }); testMathyFunction(mathy4, [-0x080000000, -0x100000000, 1, 0/0, 0, 2**53+2, -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -(2**53+2), 0x07fffffff, -0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, Number.MIN_VALUE, -(2**53), 0x100000000, 1/0, -1/0, 0x080000001, -(2**53-2), 42, 0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=819; tryItOut("Object.defineProperty(this, \"i0\", { configurable: true, enumerable: false,  get: function() {  return new Iterator(m2); } });");
/*fuzzSeed-209835301*/count=820; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"\\\"\\\\u1F0A\\\"\");");
/*fuzzSeed-209835301*/count=821; tryItOut("v0.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) { a2 = a2 + a6; var r0 = 6 / a1; var r1 = r0 % a8; a9 = a4 * r1; var r2 = 9 % 5; var r3 = 6 - 4; var r4 = a3 ^ a2; a8 = r3 % 1; a7 = 4 / 1; var r5 = a9 & a0; var r6 = a1 * r0; var r7 = a0 ^ a5; var r8 = r3 + r3; var r9 = a6 | r1; print(r8); a3 = a6 % a4; var r10 = r0 - a0; var r11 = 9 ^ r4; var r12 = r8 - r11; var r13 = a4 / r4; r2 = 8 ^ 5; var r14 = 2 | r0; var r15 = 0 & 7; var r16 = a6 * r1; var r17 = 0 * a3; var r18 = r15 & 0; var r19 = r17 & r0; var r20 = r17 & a1; var r21 = r5 & a8; var r22 = r17 | r13; var r23 = r8 * r11; var r24 = 5 * r21; print(r21); r0 = r6 / r9; var r25 = 0 * 0; var r26 = r18 ^ r24; a4 = r21 * 4; var r27 = a2 * a3; var r28 = 9 ^ r16; a2 = r16 / a5; print(r11); var r29 = r2 | r4; var r30 = r21 & x; var r31 = 5 % r6; var r32 = 5 % r16; var r33 = 8 ^ 7; a9 = r30 - 8; var r34 = r19 + r31; var r35 = r30 - 5; var r36 = x & 6; var r37 = r2 / r20; print(a8); var r38 = r17 * a5; var r39 = 8 | a4; var r40 = 8 + 1; var r41 = 5 / 6; print(r23); var r42 = a0 / r23; var r43 = r36 & r24; a5 = 0 + 0; r11 = r30 - 0; var r44 = r14 * r20; r17 = r10 | 1; var r45 = r27 * r7; var r46 = 1 + a3; var r47 = 5 / a7; r0 = r17 % 2; r7 = a2 / a1; var r48 = 0 & r37; var r49 = r17 / 1; var r50 = r40 ^ r12; var r51 = 7 % 8; var r52 = 5 | a7; var r53 = a7 - 7; var r54 = r40 | r11; var r55 = a5 + r48; var r56 = r9 | r23; r12 = 9 % x; var r57 = r4 + 2; r10 = r40 - r22; print(x); var r58 = 6 % a3; a4 = 1 - r47; r8 = r33 - r48; var r59 = a4 & r11; r0 = r17 & r17; var r60 = r48 & r48; var r61 = 0 % r31; var r62 = 0 / r28; var r63 = 5 * r56; var r64 = 1 / 1; var r65 = 4 * r17; r42 = 8 % 0; var r66 = r46 * 7; var r67 = r43 & 2; var r68 = r9 / a3; var r69 = 0 * 5; var r70 = 2 | r18; a2 = r37 & r29; var r71 = r24 * r22; var r72 = r29 / 5; var r73 = a5 - r41; var r74 = r47 % r50; var r75 = r73 & a5; var r76 = r15 + a4; var r77 = r7 | r1; r71 = r28 & a8; var r78 = r62 ^ r62; r49 = 4 | r74; r13 = a9 & 4; var r79 = r40 % r24; var r80 = r34 | r11; var r81 = r41 ^ 7; var r82 = 8 * 5; var r83 = r32 + 9; var r84 = r53 ^ r83; var r85 = r5 % r69; var r86 = 0 / 8; a9 = r54 % r78; print(r30); var r87 = 3 % a3; var r88 = r1 - r5; var r89 = r0 | r40; var r90 = r88 / 5; var r91 = r50 | r13; var r92 = r45 ^ 4; var r93 = 8 ^ r44; var r94 = r65 - r32; r61 = a6 & r40; var r95 = 3 ^ 6; r68 = 0 % r87; var r96 = 9 - 6; r21 = r62 ^ r4; var r97 = 5 + r84; var r98 = 6 ^ r48; r68 = 2 % 9; r72 = r49 + r53; var r99 = r46 + r42; var r100 = r67 - a8; print(r56); var r101 = r37 + r87; a7 = 6 | r54; print(r61); var r102 = r77 % r48; var r103 = 2 & a4; var r104 = r18 | a2; r94 = 2 - r71; var r105 = r68 | a2; var r106 = r75 * r21; var r107 = r74 + 5; var r108 = r103 + r70; r34 = r103 + 1; var r109 = r26 ^ r70; r78 = r108 ^ r98; var r110 = 3 & a7; var r111 = 4 - r70; var r112 = 0 % r35; print(a3); var r113 = r90 ^ 5; r22 = r73 / r60; var r114 = 3 / r32; var r115 = r33 ^ a2; var r116 = 6 % r39; r27 = a2 - r86; print(r30); var r117 = 0 * r109; var r118 = r2 / r39; var r119 = 4 | 7; r1 = 0 + r37; return x; });");
/*fuzzSeed-209835301*/count=822; tryItOut("v1 = (f2 instanceof m2);");
/*fuzzSeed-209835301*/count=823; tryItOut("print(x)");
/*fuzzSeed-209835301*/count=824; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((~~(2097153.0)) % (((i1)-(0x73652251))|0)))|0;\n  }\n  return f; })(this, {ff: ((10).apply).call}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0/0, -0x0ffffffff, 0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, 1.7976931348623157e308, 0.000000000000001, 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, -(2**53-2), 0, 0x0ffffffff, 42, 0x080000001, -(2**53), 0x07fffffff, 1, 2**53+2, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 2**53-2, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, 2**53, -0]); ");
/*fuzzSeed-209835301*/count=825; tryItOut("m2.set(( /x/ ), m2);");
/*fuzzSeed-209835301*/count=826; tryItOut("\"use strict\"; \"use asm\"; e2.add(/*UUV1*/( .setFloat32 = ( '' ).bind()));");
/*fuzzSeed-209835301*/count=827; tryItOut("\"use asm\"; s0 = new String;");
/*fuzzSeed-209835301*/count=828; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((( ~ (Math.acos((Math.hypot(Math.atan2(y, y), (Math.cos(Math.fround(Math.atan2(( + (( + x) / ( + y))), ( + x)))) | 0)) | 0)) | 0)) >>> 0) & ((Math.hypot(( + Math.fround(Math.cos(Math.fround(mathy2(((-0x080000001 < x) >>> 0), ( - 0/0)))))), (Math.pow(Math.imul((-1/0 | 0), (x | 0)), 0x100000000) | 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), 0/0, 1, -0x100000000, -0x100000001, -(2**53+2), 0x080000001, 0x080000000, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 0, -0, 42, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, Math.PI, 1/0, -0x0ffffffff, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-209835301*/count=829; tryItOut("g1.t2.set(a0, 18);");
/*fuzzSeed-209835301*/count=830; tryItOut("a2.pop(h2, a2, a1, p1, f1, m0);");
/*fuzzSeed-209835301*/count=831; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + (Math.acos(Math.max((( ! (( + (( + y) , x)) | 0)) | 0), (mathy0(y, (Math.asin(0x080000001) == Number.MIN_SAFE_INTEGER)) >>> 0))) >>> 0)) / Math.fround(( - Math.fround(((x % ( + Math.imul(( + (mathy0((y | 0), (y | 0)) + y)), 1.7976931348623157e308))) ** (Math.atan2(( + Math.fround(Math.expm1(Math.fround(x)))), (y >>> 0)) >>> 0)))))); }); testMathyFunction(mathy1, [-0x100000001, -Number.MIN_VALUE, 2**53, 2**53+2, -0x100000000, 1, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), 0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -(2**53-2), 2**53-2, -0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0x0ffffffff, 1.7976931348623157e308, 0/0, -0x080000000, -0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0x080000000, Number.MAX_VALUE, 0.000000000000001, -1/0, 0x080000001, 42, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=832; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + mathy0(( + ((( + (( + ( + ( + x))) + ( + Math.log1p(Math.fround(-0x080000001))))) | 0) || ((Math.imul(x, ( + x)) || Math.min((x >>> 0), (Math.max(( + Math.max((x | 0), ( + x))), y) >>> 0))) | 0))), ( + Math.fround(Math.atan2(( + Math.fround(mathy0((0x100000001 ? (Math.hypot(y, 0x07fffffff) ^ (mathy1((y | 0), (y | 0)) | 0)) : (((((((Math.atan2((-0x100000000 >>> 0), Number.MIN_SAFE_INTEGER) >>> 0) >>> 0) ? (y >>> 0) : x) >>> 0) | 0) && (x | 0)) | 0)), Math.fround(( + (( ~ x) ** (( ! (((Math.fround(y) & (-0x100000000 | 0)) | 0) >>> 0)) >>> 0))))))), ( + ( ~ Math.fround(( - x))))))))); }); testMathyFunction(mathy2, [-(2**53), 0x080000001, Number.MAX_VALUE, 2**53, 0, 1, 0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, 0/0, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, 42, 0x0ffffffff, 1/0, -0x080000000, 0x100000001, -0x100000000, 0x07fffffff, -0, 2**53+2, -0x07fffffff, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, -1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=833; tryItOut("/*RXUB*/var r = /\\1/gm; var s = \"\\n_\"; print(s.replace(r, String.prototype.search)); ");
/*fuzzSeed-209835301*/count=834; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + ( ~ ( + ( + Math.imul(( + ( + ( - y))), ( + (Math.pow(Math.fround(Math.sin(Math.fround(2**53-2))), ( ! Number.MIN_VALUE)) >>> 0))))))); }); testMathyFunction(mathy1, [0x0ffffffff, 2**53+2, 0/0, 0.000000000000001, 0x080000001, Number.MAX_VALUE, -1/0, 1, -(2**53), -0x07fffffff, -Number.MIN_VALUE, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0, -(2**53-2), -(2**53+2), 42, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000001, -0x100000000, 0x07fffffff, -0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-209835301*/count=835; tryItOut("\"use strict\"; ;/* no regression tests found */");
/*fuzzSeed-209835301*/count=836; tryItOut("g1.o0.m1.get(i0);");
/*fuzzSeed-209835301*/count=837; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    {\n      i0 = (!((((i1)-(i1))>>>(0xfffff*((+(abs((0x30f5e0ff))|0)) != (70368744177665.0)))) != (0xffffffff)));\n    }\n    i0 = (i1);\n    return (((i0)-(i1)))|0;\n    return ((0x29e4d*((0xe11e4cbe))))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=838; tryItOut("a1.length = 4;\nfor(x = d <<= e in false) m2 = a2[17];\n");
/*fuzzSeed-209835301*/count=839; tryItOut("y = allocationMarker()\u000c;print(y);");
/*fuzzSeed-209835301*/count=840; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.sin(( ~ Math.min(Math.fround((Math.fround((0 <= Math.pow(Math.cosh(y), (x >>> 0)))) / Math.fround((Math.fround(((Math.fround(y) & Math.fround(x)) >>> 0)) ? Math.fround(0x080000000) : Math.fround(0))))), ( ~ ( + (( + y) >= Math.fround(y))))))); }); testMathyFunction(mathy4, /*MARR*/[[1], null, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], null, null, null, null, null, null, null, [1], null, [1], [1], [1], [1], null, null, null, [1], null, [1], null, null, null, null, null, [1], null, null, [1], null, null, null, [1], null, null, [1], null, null, [1], [1], [1], null, null, null, [1], [1], [1], null, [1], null, [1], null, [1], [1], null, null, [1], null, null, null, [1], null]); ");
/*fuzzSeed-209835301*/count=841; tryItOut("v2 = Object.prototype.isPrototypeOf.call(a2, this.f0);function window()\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-536870911.0));\n  }\n  return f;s1 += s0;");
/*fuzzSeed-209835301*/count=842; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.asin(Math.fround(( - ( + Math.min(( - y), Math.imul(y, y))))))); }); testMathyFunction(mathy5, /*MARR*/[new String('q')]); ");
/*fuzzSeed-209835301*/count=843; tryItOut("\"use strict\"; f1 + p2;");
/*fuzzSeed-209835301*/count=844; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.max(( + mathy1((y ? ( + (mathy4((( + ((x >>> 0) || (1 >>> 0))) | 0), ((( ~ (y | 0)) | 0) | 0)) | 0)) : Math.max(Math.fround(( - ( + x))), y)), Math.cbrt(((mathy4((Math.ceil(2**53+2) | 0), Math.fround(Math.pow(Math.fround(y), y))) >>> 0) | 0)))), (( + (( + Math.ceil(0.000000000000001)) * y)) - ( + ((((( + (mathy2(y, x) | 0)) | 0) | 0) ? (y | 0) : y) | 0)))), (( + ((( ! x) | 0) | 0)) | 0)); }); testMathyFunction(mathy5, [null, '\\0', ({toString:function(){return '0';}}), (new Boolean(true)), '/0/', false, [], NaN, -0, '', (new Number(-0)), true, 1, /0/, 0.1, objectEmulatingUndefined(), (new Boolean(false)), (new Number(0)), '0', undefined, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), 0, (new String('')), [0], (function(){return 0;})]); ");
/*fuzzSeed-209835301*/count=845; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=846; tryItOut("Object.defineProperty(this, \"v2\", { configurable: 2, enumerable: (x % 3 != 0),  get: function() {  return false; } });");
/*fuzzSeed-209835301*/count=847; tryItOut("testMathyFunction(mathy4, [2**53+2, -Number.MAX_VALUE, -0, 1.7976931348623157e308, -0x080000000, 0.000000000000001, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, 0/0, -(2**53-2), Number.MAX_VALUE, -0x100000001, Math.PI, 42, -0x0ffffffff, 0x100000000, 0x0ffffffff, 1, -(2**53), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -(2**53+2), 0x100000001, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 0x07fffffff, -Number.MIN_VALUE, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=848; tryItOut("for(let [a, z] =  '' \u000c in x) v0 = Object.prototype.isPrototypeOf.call(g1.t2, e2);");
/*fuzzSeed-209835301*/count=849; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a2, [v2, timeout(1800)]);");
/*fuzzSeed-209835301*/count=850; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000000, 0x100000000, 2**53, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 42, 0/0, 1.7976931348623157e308, 0x07fffffff, 0x100000001, -0, 0x080000001, 2**53+2, 1, -(2**53-2), -Number.MAX_VALUE, -0x080000001, 1/0, -(2**53), 0.000000000000001, -0x080000000, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-209835301*/count=851; tryItOut("\"use strict\"; Object.freeze(g2.f1);");
/*fuzzSeed-209835301*/count=852; tryItOut("\"use strict\"; Array.prototype.push.call(a2, s1, t2);");
/*fuzzSeed-209835301*/count=853; tryItOut("\"use strict\"; ( '' );");
/*fuzzSeed-209835301*/count=854; tryItOut("/*MXX3*/g0.Date.prototype.getMinutes = g2.Date.prototype.getMinutes;");
/*fuzzSeed-209835301*/count=855; tryItOut("\"use strict\"; print((x %=  ));");
/*fuzzSeed-209835301*/count=856; tryItOut("t0[3];");
/*fuzzSeed-209835301*/count=857; tryItOut("{ void 0; deterministicgc(true); } print([] = x);");
/*fuzzSeed-209835301*/count=858; tryItOut("var vdxcmc = new SharedArrayBuffer(2); var vdxcmc_0 = new Int16Array(vdxcmc); vdxcmc_0[0] = 1; var vdxcmc_1 = new Int16Array(vdxcmc); print(vdxcmc_1[0]); vdxcmc_1[0] = 22; s2 += 'x';\"\\u8EF8\".unwatch(\"length\");this.e2 = new Set(i2);/*RXUB*/var r = new RegExp(\"^|.|\\\\2|(?!(^|.*)$)|[^]+?|\\\\w|\\\\b*?|\\\\2|(?!(?=(\\\\B)))|[^][^]**?|((?!(?=(?=\\\\s))|(\\\\b)*?)(?:\\\\1)|(?!\\\\D){1,}*)\", \"gim\"); var s = \"\"; print(s.replace(r, 'x')); print(this.b0);");
/*fuzzSeed-209835301*/count=859; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.log1p((Math.sin((Math.hypot(Math.ceil(y), x) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [2**53-2, 0.000000000000001, 0x080000000, -0x07fffffff, -0x080000001, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), -0x100000000, 2**53+2, -1/0, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, 1.7976931348623157e308, -0, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0x0ffffffff, Math.PI, 2**53, 1/0, 1, -0x100000001, -0x080000000, -0x0ffffffff, 42, 0/0]); ");
/*fuzzSeed-209835301*/count=860; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.max(( + ( + Math.hypot(( + Math.atan2((Math.hypot(mathy2(x, (x | 0)), y) >> ( + ( + Math.tanh(( + y))))), (y % (( + y) / y)))), ( + Math.imul(( + ( + ( ! ( + (x , (-Number.MIN_SAFE_INTEGER | 0)))))), (Math.hypot(((x || 0x07fffffff) | 0), (x | 0)) | 0)))))), ( + Math.pow((Math.log((((( ! x) & Math.hypot(-0x080000000, Math.log10(y))) === (((((x >>> 0) + 0x0ffffffff) | 0) | 0) == (x | 0))) >>> 0)) >>> 0), (( + ((( + (1 | 0)) | 0) | 0)) | 0))))); }); ");
/*fuzzSeed-209835301*/count=861; tryItOut("s1 += s0;");
/*fuzzSeed-209835301*/count=862; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( - ((((Math.atan2((mathy0(y, ((mathy0(((mathy0((Math.min(Math.fround(y), (x | 0)) | 0), x) | 0) >>> 0), (x >>> 0)) >>> 0) >>> 0)) | 0), (0.000000000000001 | 0)) | 0) >>> 0) << (Math.ceil((y ? 1 : ( + Math.atan2(-Number.MIN_SAFE_INTEGER, y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[(-1), objectEmulatingUndefined(), (-1), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Boolean(true), new Boolean(true), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-209835301*/count=863; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?![^])\", \"\"); var s = \"\\uff12\"; print(uneval(s.match(r))); \n/* no regression tests found */\n");
/*fuzzSeed-209835301*/count=864; tryItOut("\"use strict\"; v1 + g1.t2;");
/*fuzzSeed-209835301*/count=865; tryItOut("v0 = new Number(f2);");
/*fuzzSeed-209835301*/count=866; tryItOut("for(var a = /(?!\\1\\b)/g in  /x/g ) print(x);");
/*fuzzSeed-209835301*/count=867; tryItOut("mathy0 = (function(x, y) { return (((( + ( ~ Math.tan(Math.asin(y)))) >>> 0) >>> ( + (Math.abs(((y ? Math.fround(( ! Number.MIN_VALUE)) : (((( ! x) | 0) * (( + Math.min(Math.min(y, x), (0.000000000000001 | 0))) | 0)) | 0)) >>> 0)) | 0))) | 0); }); ");
/*fuzzSeed-209835301*/count=868; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\u00a9+?$^\\\\d|\\\\2|\\\\xA5.[\\\\cL-\\\\cY\\\\u00B9-\\\\u00Da]|.+?|(?=[^]+){3}{1,}\", \"y\"); var s = \"\\u00a9\\u00fa\\n\\u00fa\\n\\u00fa\\n\\u6dcd\\u6dcd\\u6dcd\\u6dcd\\u6dcd\\u6dcd\\u6dcd\\u6dcd\"; print(s.replace(r, (let (e=eval) e))); ");
/*fuzzSeed-209835301*/count=869; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log10((((Math.hypot(mathy0(mathy1(y, y), ( + (((y >>> 0) == y) | 0))), Math.atanh(x)) | 0) || mathy1((y >>> 0), (( - (((x >>> 0) ? ( + Math.imul(( + -(2**53+2)), y)) : ( + y)) | 0)) | 0))) | 0)); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x07fffffff, 2**53+2, 2**53, -(2**53+2), -0x080000001, -0x080000000, 0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, Number.MAX_VALUE, -0x100000000, 0, -0x0ffffffff, -(2**53), 42, 0/0, Math.PI, 0x080000000, -0, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0, 1, 0x100000000, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=870; tryItOut("testMathyFunction(mathy3, [Math.PI, -0, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, 0x100000000, 2**53-2, 0/0, -0x07fffffff, -(2**53+2), 2**53+2, 0, -0x100000001, 1, 0x100000001, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 1.7976931348623157e308, 1/0, 0x080000001, 0x0ffffffff, -0x080000001, 0x080000000, -(2**53-2), -0x0ffffffff, 0x07fffffff, -1/0]); ");
/*fuzzSeed-209835301*/count=871; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=872; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return ( ~ ( + (Math.hypot(Math.round(Math.fround((((y >>> 0) >>> (x < ( ~ 0x0ffffffff))) >>> 0))), 0x080000001) < Math.fround((Math.fround((Math.max((0x080000001 >>> 0), (Math.trunc(Math.fround(-Number.MIN_VALUE)) >>> 0)) >>> 0)) != (((( ~ -0) >>> x) | 0) >> y)))))); }); ");
/*fuzzSeed-209835301*/count=873; tryItOut("o0.v0 = false;");
/*fuzzSeed-209835301*/count=874; tryItOut("\"use strict\"; f1 + o2;");
/*fuzzSeed-209835301*/count=875; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.fround(Math.min(Math.fround((( ~ Math.hypot(Math.fround(x), (( + -(2**53+2)) >>> 0))) << (Math.log1p(1) >>> 0))), Math.fround(((( + Math.cbrt(( + y))) - ((((0 | 0) - ((Math.sin(((Math.acos((Math.log(y) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [0, -(2**53-2), Math.PI, Number.MAX_VALUE, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, -0, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_VALUE, -1/0, -0x080000001, -0x100000000, -0x080000000, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, 2**53+2, 0/0, 2**53, 1.7976931348623157e308, -Number.MIN_VALUE, 42, 1]); ");
/*fuzzSeed-209835301*/count=876; tryItOut("a0 = arguments;");
/*fuzzSeed-209835301*/count=877; tryItOut("var iuzisb = new ArrayBuffer(16); var iuzisb_0 = new Int8Array(iuzisb); iuzisb_0[0] = -27; var iuzisb_1 = new Float64Array(iuzisb); print(iuzisb_1[0]); iuzisb_1[0] = 26; var iuzisb_2 = new Uint32Array(iuzisb); var iuzisb_3 = new Uint8Array(iuzisb); iuzisb_3[0] = 9; var iuzisb_4 = new Int32Array(iuzisb); iuzisb_4[0] = -28; var iuzisb_5 = new Int32Array(iuzisb); iuzisb_5[0] = 23; var iuzisb_6 = new Float64Array(iuzisb); iuzisb_6[0] = -11; return;/*oLoop*/for (let vbhjtp = 0,  /x/ ; vbhjtp < 83; /(?:(\\3+))(?:\\d?)|[^\\S\\d](?:[\\u00c4-\u3204]){4,}([^])*?/yim, ++vbhjtp) { a2[7] = \"\\u244D\"; } h1.iterate = (function() { try { (void schedulegc(g0)); } catch(e0) { } try { a2.unshift(s0, f1, y, this, s1,  \"\" , o2.g0.o0.e1, h0); } catch(e1) { } try { s0 += s2; } catch(e2) { } s1 = g0.t0[13]; return g1.o0.o0.m2; });a1.sort((function() { try { h2.enumerate = (function() { a2 = a0.filter((function() { for (var j=0;j<133;++j) { f1(j%2==1); } })); return this.h1; }); } catch(e0) { } o1 = new Object; return h1; }));v2 = -0;s0 += 'x';b1 = t1.buffer; /x/ ;");
/*fuzzSeed-209835301*/count=878; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=879; tryItOut("mathy5 = (function(x, y) { return (Math.fround(( ~ ( ~ Math.fround(Math.min((Number.MAX_SAFE_INTEGER || 0x0ffffffff), x))))) ** (( + (( + ( + (Math.fround(0/0) << ( + Math.pow(x, 0x0ffffffff))))) == ( + (Math.fround((x & Math.fround(x))) <= (Math.max((1 < mathy0(0/0, x)), (Math.fround(Math.pow(Math.fround(x), Math.fround(y))) >>> 0)) >>> 0))))) / mathy3((( + (( + (x >= x)) >>> ( + y))) >>> 0), mathy3((x | 0), mathy4((x || x), ( + x)))))); }); testMathyFunction(mathy5, [-(2**53-2), 2**53-2, 0, 0.000000000000001, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 2**53, -(2**53+2), -0, 0/0, -0x100000001, Math.PI, 42, -0x080000000, 1.7976931348623157e308, 0x07fffffff, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), -0x07fffffff, 1, -1/0, 0x100000000, 1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=880; tryItOut("for([z, z] = x in (4277)) var this.h2 = {};");
/*fuzzSeed-209835301*/count=881; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow((Math.hypot((Math.max(Math.max(Math.atan2(x, (( - Math.pow(x, x)) | 0)), y), (( + x) | 0)) | 0), ((Math.log((x >>> 0)) >>> 0) | 0)) >>> 0), ( - (( ~ (Math.sin(x) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 0/0, 0x100000000, -0x080000000, 1/0, -0x0ffffffff, -1/0, 0, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), 2**53, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -(2**53-2), Number.MIN_VALUE, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 1.7976931348623157e308, 42, -0x080000001, -Number.MAX_VALUE, 1, -0x100000000, -0x07fffffff, Number.MAX_VALUE, 2**53+2, 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=882; tryItOut("with((get = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: offThreadCompileScript, getOwnPropertyNames: Int32Array, delete: function(name) { return delete x[name]; }, fix: undefined, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(this), Math.cos,  /x/ )))const x, lehegj, y, \u3056, jcprgt, x, urxrlk;m1.get(b1);");
/*fuzzSeed-209835301*/count=883; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=884; tryItOut("try { let a = (4277), eval = x, bjpgzk;print(x); } finally { for(let a of /*MARR*/[false, false, function(){}, function(){}, function(){}, false, function(){}, false, false, function(){}, false, function(){}, false, false, function(){}]) for(let c in /*MARR*/[(void 0), objectEmulatingUndefined(), (0/0), (0/0), (void 0), (0/0), (void 0), objectEmulatingUndefined(), (void 0), (0/0), (0/0), (void 0), (void 0), objectEmulatingUndefined()]) throw c; } for(let e of eval = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: Object.create, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })( /x/ ), ({min: \"\\uEADE\" }) ? ([]) : x)) e.fileName;");
/*fuzzSeed-209835301*/count=885; tryItOut("h0 + f0;");
/*fuzzSeed-209835301*/count=886; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min(((( + mathy2(Math.fround(Math.min((x | 0), Math.fround(( - x)))), Math.atan(x))) / ( + (( ~ ( + (Math.acos((x >>> 0)) , x))) | (( - ( + ( + ( + x)))) | 0)))) >>> 0), (Math.imul(x, ( + ((( + mathy2(( + y), ( + y))) >>> 0) ^ Math.fround(( + Math.max(Math.atan2(x, x), ( + Math.imul(x, -(2**53))))))))) ? ( + (Math.tanh((x >>> 0)) == x)) : ( ~ mathy1(x, (Math.ceil(Math.fround(x)) >>> 0))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 42, -(2**53), 2**53, -(2**53+2), 0x100000000, 2**53-2, 0/0, -0, 0x07fffffff, Math.PI, -0x0ffffffff, 0x080000000, -0x100000001, -0x080000000, 0.000000000000001, 0x100000001, -1/0, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0, 1, 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=887; tryItOut("s0 = '';");
/*fuzzSeed-209835301*/count=888; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a0, [true]);");
/*fuzzSeed-209835301*/count=889; tryItOut("mathy5 = (function(x, y) { return Math.tan((Math.pow(mathy0(Math.fround(Math.acosh(Math.fround((Math.trunc(x) | 0)))), ( + mathy1(( + (x >= ( + Math.atan2(y, Math.PI)))), ((Math.abs(( + (Math.tanh(y) >>> 0))) >>> 0) | 0)))), ((( + y) && (Math.sqrt(Math.fround(( - Math.fround(((( + (( + -Number.MIN_VALUE) ? ( + y) : ( + y))) >>> ( + mathy3(x, x))) >>> 0))))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-(2**53-2), 0x0ffffffff, -0, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, -Number.MIN_VALUE, 1/0, -0x0ffffffff, -0x080000001, Number.MIN_VALUE, -0x100000001, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 0, 0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, -(2**53+2), 0/0, 0x07fffffff, 1.7976931348623157e308, 1, -(2**53), 42]); ");
/*fuzzSeed-209835301*/count=890; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.fround(Math.log((Math.fround((Math.atanh(-0x080000001) ? Math.fround((y ? Math.hypot(-0x0ffffffff, y) : x)) : Math.fround(Math.atan((((Math.tanh(2**53) >>> 0) ^ (x >>> 0)) >>> 0))))) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[ \"use strict\" ,  '\\0' ,  \"use strict\" , false,  \"use strict\" , false, false,  '\\0' ,  \"use strict\" ,  '\\0' ,  '\\0' , false, false,  '\\0' ,  \"use strict\" , false,  \"use strict\" , false,  \"use strict\" ,  \"use strict\" ,  '\\0' ,  '\\0' ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , false, false, false, false, false, false]); ");
/*fuzzSeed-209835301*/count=891; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - Math.tan(Math.log10((Math.pow((((Math.exp((y >>> 0)) >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0), y) | 0)))); }); testMathyFunction(mathy4, [-0x080000001, -0x100000000, -Number.MIN_VALUE, 2**53+2, 1/0, 0x080000000, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, -(2**53+2), Math.PI, -0x100000001, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, Number.MAX_SAFE_INTEGER, 42, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, 2**53, -0, 0/0, Number.MAX_VALUE, 0x100000001, 0, 1, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=892; tryItOut("{ void 0; gcslice(827334679); } yield -24;function w() { yield ( /x/g  >>  /x/ ) & /*FARR*/[...[], , , window, [[]], ...[],  /x/ , ...[], ...[]].map } a1.splice(10, 12, g1.a1, v0);");
/*fuzzSeed-209835301*/count=893; tryItOut("const ripbqn, x, xhgvyv, x, sdoqqv, ijnivy, dltujq\u000c;/*ODP-3*/Object.defineProperty(f2, \"toDateString\", { configurable: false, enumerable: (x % 2 != 0), writable: (x % 4 != 0), value: e1 });");
/*fuzzSeed-209835301*/count=894; tryItOut("var hseufc = new SharedArrayBuffer(12); var hseufc_0 = new Uint16Array(hseufc); hseufc_0[0] = -27; v2 = r1.flags;((4277));");
/*fuzzSeed-209835301*/count=895; tryItOut("mathy4 = (function(x, y) { return ( - (( ! ((x != ( + x)) | 0)) >>> 0)); }); testMathyFunction(mathy4, [0, 2**53, 1.7976931348623157e308, 1, 0x100000000, 2**53-2, -(2**53-2), -(2**53), 0x0ffffffff, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -0x080000001, 2**53+2, -Number.MIN_VALUE, 0/0, -0, -0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 0x080000001, Math.PI, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 42]); ");
/*fuzzSeed-209835301*/count=896; tryItOut("");
/*fuzzSeed-209835301*/count=897; tryItOut("/*infloop*/for(var this.zzz.zzz in (((let (e=eval) e))(x))){var bbeyni, x =  /x/ , htwfvd;-28;/*RXUB*/var r = r0; var s = s1; print(s.split(r)); print(r.lastIndex);  }");
/*fuzzSeed-209835301*/count=898; tryItOut("/*ODP-1*/Object.defineProperty(g1.i2, \"valueOf\", ({enumerable: false}));");
/*fuzzSeed-209835301*/count=899; tryItOut("/*tLoop*/for (let z of /*MARR*/[new String(''), 0x100000001, new String(''), 0x2D413CCC, (-0), (1/0), (-0), new String(''), 0x2D413CCC, (1/0), 0x100000001, 0x2D413CCC, 0x2D413CCC, new String(''), 0x100000001, 0x100000001, (1/0), 0x100000001, (-0), 0x100000001, (1/0), new String(''), 0x100000001, new String(''), 0x2D413CCC, 0x100000001, new String(''), 0x2D413CCC, 0x2D413CCC, (1/0), 0x2D413CCC, (1/0), (-0), new String(''), 0x2D413CCC, new String(''), new String(''), (-0), new String(''), (-0), (-0), (1/0), (-0), (1/0), 0x100000001, 0x2D413CCC, (1/0), 0x2D413CCC, (-0), 0x2D413CCC, new String(''), (1/0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (1/0), 0x2D413CCC, (-0), 0x100000001, 0x2D413CCC, (-0), new String(''), (1/0), new String(''), (1/0), 0x2D413CCC, 0x100000001, new String(''), 0x100000001, (-0), 0x2D413CCC, 0x2D413CCC, 0x100000001, 0x100000001, (1/0), new String(''), (-0), (1/0), 0x2D413CCC, new String(''), (1/0), (-0), (1/0), (-0), (-0), new String(''), (1/0), 0x2D413CCC, (-0), new String(''), new String(''), (-0), new String(''), 0x100000001, 0x2D413CCC, 0x100000001, (1/0), 0x2D413CCC, (-0), 0x100000001, (-0), (-0), (1/0), (-0), (1/0), 0x100000001, new String(''), 0x2D413CCC, 0x100000001, 0x100000001, (1/0), new String('')]) { o1.v0 = t0.byteLength; }");
/*fuzzSeed-209835301*/count=900; tryItOut("\"use strict\"; o1.o2.i1.next();");
/*fuzzSeed-209835301*/count=901; tryItOut("\"use strict\"; a1.forEach(f0, g0);");
/*fuzzSeed-209835301*/count=902; tryItOut("h2.getPropertyDescriptor = this.f1;");
/*fuzzSeed-209835301*/count=903; tryItOut("/*RXUB*/var r = /\\2/im; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-209835301*/count=904; tryItOut("\"use strict\"; m1.has(e0);");
/*fuzzSeed-209835301*/count=905; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + (Math.sinh(((Math.log1p((x | 0)) + ( + Math.expm1(Math.tanh(Math.asinh(y))))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-209835301*/count=906; tryItOut("mathy2 = (function(x, y) { return Math.acosh(( ~ (mathy0((Math.expm1(-0x100000000) >>> 0), Math.fround(Math.imul(Math.fround(mathy1(Math.fround((Math.fround(y) >>> 0)), Math.fround(( + Math.asin(( + x)))))), x))) | 0))); }); testMathyFunction(mathy2, [0, 0.1, (new Number(-0)), true, '', [0], '0', undefined, -0, (new Number(0)), (function(){return 0;}), '/0/', '\\0', ({valueOf:function(){return 0;}}), false, (new Boolean(true)), objectEmulatingUndefined(), [], /0/, NaN, null, 1, (new String('')), (new Boolean(false)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-209835301*/count=907; tryItOut("o1.g2.offThreadCompileScript(\"var w = (makeFinalizeObserver('nursery'));this.v0 = t1.BYTES_PER_ELEMENT;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 == 2), noScriptRval: (x % 3 != 0), sourceIsLazy: false, catchTermination: (x % 5 == 2) }));");
/*fuzzSeed-209835301*/count=908; tryItOut("\"use strict\"; print(f2);function w() { \"use strict\"; return ({w: [, [], [[[[], , [], []], c, , , x], ], [[NaN, [, ], ], x(window), {x, x: x}]], x, callee: {}, x: x}) = x } v0 = Object.prototype.isPrototypeOf.call(a1, f0);");
/*fuzzSeed-209835301*/count=909; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    d1 = (-128.0);\n    i0 = ((((i3)+((d1) != (+(-1.0/0.0))))>>>((((-0xfb0a09) ? (0x69cdbd8a) : (0xf954d20a)) ? (i0) : (i0))*-0xd675f)));\n    i3 = ((imul((!(0x3c9236aa)), ((((0x36f9ff8c) == (((/*FFI*/ff(((-0x8000000)), ((-4097.0)), ((-34359738369.0)), ((0.0009765625)), ((1.5474250491067253e+26)), ((1.5474250491067253e+26)), ((17.0)), ((-3.0)), ((-6.044629098073146e+23)), ((34359738369.0)), ((65.0)), ((134217728.0)), ((17179869185.0)), ((0.00390625)), ((73786976294838210000.0)))|0))>>>((0x1227d28c) / (0x14c485ae))))*-0xfffff)))|0));\n    d1 = (d1);\n    {\n      i2 = (i3);\n    }\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000000, 0x080000001, 0, -0x080000001, -1/0, 0x080000000, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, -(2**53), Math.PI, 2**53+2, 0x100000001, -Number.MIN_VALUE, -(2**53+2), 1/0, Number.MIN_VALUE, 1, -0, 0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, -0x100000000, 0.000000000000001, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=910; tryItOut("a2.forEach((function mcc_() { var qeyfys = 0; return function() { ++qeyfys; f1(/*ICCD*/qeyfys % 8 == 4);};})(), f1, a0);");
/*fuzzSeed-209835301*/count=911; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"(?=(?:(?!((?![^])\\\\b{0})|\\uc63c*){1,}))\", \"yim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=912; tryItOut("\"use strict\"; /*oLoop*/for (rfxwkd = 0; rfxwkd < 53; (4277), ++rfxwkd) { /*vLoop*/for (let waiprk = 0; waiprk < 99; ++waiprk) { var a = waiprk; e2.has(t0); }  } ");
/*fuzzSeed-209835301*/count=913; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround(Math.cosh(Math.fround(Math.max(mathy0(0.000000000000001, x), Math.fround(Math.atan2(Math.fround(Math.sign(x)), (( ! -0x100000000) >>> 0))))))) / (((( + -0x0ffffffff) !== ( + y)) / ((Math.asinh(mathy4(y, y)) > y) | 0)) ? ( + Math.min((Math.fround(Math.hypot(( + x), Math.fround(y))) | 0), (((x ^ mathy3(Math.tanh(y), y)) + Math.asin(Math.fround(x))) | 0))) : ( + mathy0(( + (( + ( - ( ! (y | 0)))) + (Math.fround(( ! y)) >>> 0))), Math.fround(Math.hypot(Math.sin((y / Math.fround(y))), x)))))); }); testMathyFunction(mathy5, [Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 0/0, 42, -Number.MIN_VALUE, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 0x080000001, 2**53+2, -0x080000000, -1/0, 0, 1/0, -0x080000001, 0x100000001, 2**53, -(2**53+2), -0x0ffffffff, 0x100000000, Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-209835301*/count=914; tryItOut("g0.a2[2] = a0;");
/*fuzzSeed-209835301*/count=915; tryItOut("\"use strict\"; a1.sort(DataView.prototype.getUint8);");
/*fuzzSeed-209835301*/count=916; tryItOut("b1 + '';");
/*fuzzSeed-209835301*/count=917; tryItOut("this.v2 = b0.byteLength;");
/*fuzzSeed-209835301*/count=918; tryItOut("\"use strict\"; v2 = evaluate(\"function f0(e2) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = 1.9342813113834067e+25;\\n    var d3 = 3.022314549036573e+23;\\n    (Float32ArrayView[1]) = ((Float32ArrayView[0]));\\n    i1 = (0x6f74bed1);\\n    d3 = (2049.0);\\n    i1 = ((((-0x8000000)*-0x9e47e)>>>(((+abs(((d3)))) > (d3))-(i0))));\\n    d2 = (-3.094850098213451e+26);\\n    return +((-140737488355327.0));\\n  }\\n  return f;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 0), noScriptRval: (x % 2 == 0), sourceIsLazy: (new (function  a (x, x) { \"use strict\"; for (var v of b0) { e1.has(e1); } } )(new String.prototype.fontsize())), catchTermination: false }));");
/*fuzzSeed-209835301*/count=919; tryItOut("\"use strict\"; h1.set = f1;");
/*fuzzSeed-209835301*/count=920; tryItOut("mathy2 = (function(x, y) { return (( ! Math.fround(( + mathy1(Math.fround((( + (( ! (y | 0)) ? y : Math.fround((( + (-1/0 | 0)) >>> 0)))) >>> Math.abs(( ~ Math.fround(-Number.MIN_VALUE))))), ( + ( ~ ( - ( + ( ~ (Math.cos(x) | 0)))))))))) | 0); }); testMathyFunction(mathy2, [0x0ffffffff, 0.000000000000001, 0/0, 1.7976931348623157e308, Math.PI, -(2**53), -(2**53-2), 2**53, -0x0ffffffff, -0x100000000, 42, -Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, 1/0, 0, 0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, Number.MAX_VALUE, -(2**53+2), 0x100000000, -0, 1, 0x080000001, 0x080000000]); ");
/*fuzzSeed-209835301*/count=921; tryItOut("mathy5 = (function(x, y) { return (Math.tan(( ~ ( ! Math.sqrt(Math.sin(y))))) | 0); }); testMathyFunction(mathy5, [Math.PI, 2**53-2, 0x0ffffffff, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 1, -0x080000000, 0, Number.MAX_VALUE, 1/0, -0x100000000, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -0x0ffffffff, 1.7976931348623157e308, -(2**53), -(2**53+2), -(2**53-2), -1/0, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, 42, -0]); ");
/*fuzzSeed-209835301*/count=922; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=923; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0(( + (( + mathy1((-(2**53+2) | 0), (Math.log10(Math.fround(x)) | 0))) !== ( + Math.fround(mathy0(Math.fround(( + Math.sinh(( + y)))), Math.fround(Math.fround((Math.fround(y) !== Math.fround(( ~ Math.fround(Math.fround(((y | 0) ? Math.fround(x) : Math.fround(-Number.MAX_VALUE)))))))))))))), (Math.fround(y) <= ( ! ( ! Math.asinh(y))))) == ( - Math.round(Math.fround(( ! Math.fround(y)))))); }); testMathyFunction(mathy2, [0x07fffffff, -(2**53-2), 1.7976931348623157e308, 0, -0x100000000, Math.PI, 0x0ffffffff, -0x100000001, -0x080000001, 42, 0x080000000, Number.MIN_VALUE, 0x080000001, -(2**53+2), -0x0ffffffff, 1/0, -0, 0.000000000000001, 2**53+2, -0x07fffffff, 0/0, 2**53-2, 1, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, 2**53, -Number.MIN_VALUE, 0x100000001, -(2**53), -Number.MAX_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=924; tryItOut("y = x;");
/*fuzzSeed-209835301*/count=925; tryItOut("g0.a2 = new Array;");
/*fuzzSeed-209835301*/count=926; tryItOut("yield;x;");
/*fuzzSeed-209835301*/count=927; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0, /0/, (new Number(0)), undefined, null, NaN, (new String('')), (function(){return 0;}), (new Boolean(true)), ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), '\\0', -0, 1, ({toString:function(){return '0';}}), false, (new Boolean(false)), [0], '', (new Number(-0)), '0', '/0/', objectEmulatingUndefined(), [], true, 0.1]); ");
/*fuzzSeed-209835301*/count=928; tryItOut("mathy0 = (function(x, y) { return (Math.hypot((( + Math.atan2(Math.fround(( + ( ! ( + ( ! x))))), (Math.min(Math.fround(x), Math.max(Math.imul(Math.sqrt(y), ( ! Math.pow(x, (y | 0)))), Math.atanh(x))) >>> 0))) >>> 0), (((((( ! (((Math.fround(2**53) >>> 0) < (y >>> 0)) >>> 0)) >>> 0) >>> 0) && (Math.fround(Math.min(Math.fround(y), Math.atan(((-0x080000001 ** x) >>> 0)))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x100000000, 1/0, 1, Math.PI, -Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0, -1/0, 0x100000001, 2**53, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 0, 42, 0x080000000, 0.000000000000001, 0x100000000, -0x07fffffff, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 0/0, -(2**53), Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=929; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_VALUE, 0, Math.PI, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x0ffffffff, 0x080000000, -(2**53-2), 2**53, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0/0, -0x07fffffff, 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, -0x100000001, -1/0, -(2**53+2), -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, 0x100000001, 1/0, 2**53+2, -0x080000001, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=930; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), 0.000000000000001, 0, -0x080000000, -Number.MAX_VALUE, 2**53, -0x080000001, -0x07fffffff, 0/0, -0x100000001, -(2**53+2), Math.PI, 0x07fffffff, -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0, -Number.MIN_VALUE, 1/0, 0x100000001, 42, Number.MIN_VALUE, 0x080000001, 2**53+2, 0x080000000, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-209835301*/count=931; tryItOut("/*RXUB*/var r = /(?!\\f)((?=\\B{0,}\\B|(^)))($[^]|.*?(\\w{4,}))?/gym; var s = \"\"; print(s.match(r)); print(r.lastIndex); c = x;");
/*fuzzSeed-209835301*/count=932; tryItOut("\"use strict\"; h2.enumerate = (function() { try { i1 + ''; } catch(e0) { } this.a0.push(i2, f2); throw t1; });function NaN() { \"use strict\"; s2.__proto__ = p0; } /*infloop*/for(var x in this) v2 = (p1 instanceof p2);");
/*fuzzSeed-209835301*/count=933; tryItOut("with( /x/g )(window);");
/*fuzzSeed-209835301*/count=934; tryItOut(";let z = (Object.defineProperty(d, \"__parent__\", ({get: w =>  { \"use strict\"; print(x); } , set: ({constructor: ((function factorial(jshrqo) { m0.set(m2, a2);; if (jshrqo == 0) { print(uneval(g1.o0));; return 1; } ; return jshrqo * factorial(jshrqo - 1);  })(2)) }), enumerable: true})));");
/*fuzzSeed-209835301*/count=935; tryItOut("print(v1);");
/*fuzzSeed-209835301*/count=936; tryItOut("a1.sort((function(j) { if (j) { try { v1 = g0.runOffThreadScript(); } catch(e0) { } try { a0 + ''; } catch(e1) { } try { h1.defineProperty = (function(j) { if (j) { m2.toString = (function mcc_() { var tfoojw = 0; return function() { ++tfoojw; if (/*ICCD*/tfoojw % 5 == 2) { dumpln('hit!'); try { g2.o2.t0.set(t0, o0.v2); } catch(e0) { } try { g2.t2[8] = o2.i0; } catch(e1) { } o0.__proto__ = m2; } else { dumpln('miss!'); e1 = new Set(p1); } };})(); } else { try { v0 = t2.BYTES_PER_ELEMENT; } catch(e0) { } try { e2.delete(\u3056 = undefined); } catch(e1) { } try { p2 + ''; } catch(e2) { } a2.pop(); } }); } catch(e2) { } v2 = t1.length; } else { try { a2 = a1.slice(-3, NaN); } catch(e0) { } try { t2 + a2; } catch(e1) { } a2.reverse(); } }));");
/*fuzzSeed-209835301*/count=937; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy0(( + ( + ( + (( ~ (((x | 0) + (x | 0)) | 0)) >>> 0)))), ((( + Math.imul((mathy1(y, -Number.MAX_VALUE) >>> 0), ( + Math.abs(((Math.atan2((0x080000000 >>> 0), Math.fround(y)) >>> 0) | 0))))) | (( + (( + mathy1(Math.fround(x), Math.asinh(x))) & Math.imul(Math.fround(( ! Math.fround(x))), mathy0((( + y) | 0), Math.pow(y, x))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-(2**53+2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, Number.MIN_VALUE, 1, -1/0, 0.000000000000001, -Number.MIN_VALUE, 42, -(2**53), 0x07fffffff, -0x100000000, 2**53+2, 2**53, -0x0ffffffff, -Number.MAX_VALUE, 1/0, 1.7976931348623157e308, 0x100000000, 0, 2**53-2, -0x080000000, 0x080000000, 0x080000001, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=938; tryItOut("\"use strict\"; i0.send(this.h2);");
/*fuzzSeed-209835301*/count=939; tryItOut("\"use strict\"; a0 = Array.prototype.slice.apply(a1, [NaN, NaN, i2]);");
/*fuzzSeed-209835301*/count=940; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.log10(Math.pow(Math.max(Math.log(( - y)), Math.atan(x)), Math.atan2(Math.hypot(-0, x), ( + x)))); }); testMathyFunction(mathy0, [2**53-2, Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, 0x100000001, -0x080000001, 2**53+2, -0x07fffffff, -0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, 42, 0, -1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, -0, -Number.MAX_VALUE, 2**53, Math.PI, 1/0, -(2**53), 1, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -0x080000000, -0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=941; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 != 0), sourceIsLazy:  /x/g , catchTermination: (x % 6 != 1) }));");
/*fuzzSeed-209835301*/count=942; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.acosh((( ! ( - (( ~ ((Number.MIN_SAFE_INTEGER ** Math.fround(Number.MAX_SAFE_INTEGER)) | 0)) | 0))) | 0)) | 0); }); testMathyFunction(mathy5, [2**53, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 0.000000000000001, -0x080000001, -1/0, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), Math.PI, 0x080000000, 0, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, 42, -0x07fffffff, 1, -0x0ffffffff, 2**53+2, 0/0, 0x0ffffffff, -0x100000001, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-209835301*/count=943; tryItOut("s0 + '';");
/*fuzzSeed-209835301*/count=944; tryItOut("s0 += this.s1;");
/*fuzzSeed-209835301*/count=945; tryItOut("testMathyFunction(mathy4, [0.000000000000001, -0x080000000, -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -0, Number.MIN_VALUE, -0x080000001, Math.PI, -Number.MIN_VALUE, 2**53-2, 0x100000000, -0x0ffffffff, 1/0, 0/0, -1/0, 0x100000001, 2**53, -(2**53-2), -0x100000000, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-209835301*/count=946; tryItOut("let (y) { selectforgc(o2); }");
/*fuzzSeed-209835301*/count=947; tryItOut("e2.add(h2);");
/*fuzzSeed-209835301*/count=948; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( ! Math.log10((mathy1(( + Math.PI), Math.ceil(-0x080000001)) | 0)))); }); testMathyFunction(mathy5, [2**53-2, 0, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, 1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0/0, 0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, -0, 0x07fffffff, -0x100000001, -0x080000001, 0.000000000000001, 0x100000001, Math.PI, -0x100000000, -(2**53-2), 0x080000001, -0x07fffffff, 2**53, -(2**53), 1.7976931348623157e308, 0x080000000, 42]); ");
/*fuzzSeed-209835301*/count=949; tryItOut("this.v2 = evalcx(\"/* no regression tests found */\", g0);");
/*fuzzSeed-209835301*/count=950; tryItOut("with({d: (4277)}){i1.send(p0);print((4277)); }");
/*fuzzSeed-209835301*/count=951; tryItOut("Array.prototype.push.apply(g0.a1, [v2, m0, this.m2, f0, b2]);");
/*fuzzSeed-209835301*/count=952; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=953; tryItOut("return String.prototype.match = (x << e);\n/* no regression tests found */\n");
/*fuzzSeed-209835301*/count=954; tryItOut("switch(NaN) { default: t2.set(t1, 8);case 4: break; case x: break; case (function(y) { return  /x/g  }).call( /x/g , [z1], new RegExp(\"\\\\x2E\", \"gm\")) ? Object.prototype.__lookupSetter__.prototype : (void options('strict')): break;  }");
/*fuzzSeed-209835301*/count=955; tryItOut("\"use strict\"; v0 = (t1 instanceof this.f2);");
/*fuzzSeed-209835301*/count=956; tryItOut("\"use strict\"; a1[8];");
/*fuzzSeed-209835301*/count=957; tryItOut("M:with((timeout(1800)))Array.prototype.sort.apply(a2, [(function() { try { h1 = ({getOwnPropertyDescriptor: function(name) { Object.preventExtensions(f1);; var desc = Object.getOwnPropertyDescriptor(v0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { o1.i2 = new Iterator(g0);; var desc = Object.getPropertyDescriptor(v0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { m0 + e2;; Object.defineProperty(v0, name, desc); }, getOwnPropertyNames: function() { g2.i2 = new Iterator(f0);; return Object.getOwnPropertyNames(v0); }, delete: function(name) { Array.prototype.shift.call(o1.a1, v1, h0, m2);; return delete v0[name]; }, fix: function() { o2.m1.has(b2);; if (Object.isFrozen(v0)) { return Object.getOwnProperties(v0); } }, has: function(name) { b2 = Proxy.create(h1, o1.a1);; return name in v0; }, hasOwn: function(name) { e1.add(\"\\u7587\");; return Object.prototype.hasOwnProperty.call(v0, name); }, get: function(receiver, name) { e1.add(e1);; return v0[name]; }, set: function(receiver, name, val) { throw a0; v0[name] = val; return true; }, iterate: function() { Array.prototype.splice.call(a0);; return (function() { for (var name in v0) { yield name; } })(); }, enumerate: function() { for (var p in this.g0) { try { g2.valueOf = (function() { for (var j=0;j<114;++j) { f0(j%2==1); } }); } catch(e0) { } try { m2 + ''; } catch(e1) { } try { print(uneval(v1)); } catch(e2) { } a0.pop(m1, /([^]|(?:^)|(?![^])*){1,4}/g, m1); }; var result = []; for (var name in v0) { result.push(name); }; return result; }, keys: function() { a2 = [];; return Object.keys(v0); } }); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { (void schedulegc(g0)); } catch(e2) { } for (var v of p2) { try { /*RXUB*/var r = r1; var s = s2; print(s.search(r));  } catch(e0) { } try { v2 = evalcx(\"print(x);\", g0); } catch(e1) { } try { selectforgc(o1); } catch(e2) { } /*ADP-1*/Object.defineProperty(g2.a0, 7, ({enumerable: true})); } return t0; }), e1, x **= let (z = window) window]);");
/*fuzzSeed-209835301*/count=958; tryItOut("\"use asm\"; testMathyFunction(mathy0, [Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), 0, 1/0, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, 2**53, -0x100000001, 0x080000001, 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, 0x07fffffff, -0, -1/0, -(2**53-2), -(2**53+2), 0/0, Number.MAX_VALUE, 0x080000000, 0x100000000, 1]); ");
/*fuzzSeed-209835301*/count=959; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.max(Math.hypot((((Math.PI | 0) , (( + x) | 0)) | 0), ( + Math.fround(Math.max(Math.fround((x & Math.fround((( + x) === Math.fround(x))))), Math.fround((Math.fround(y) >>> x)))))), (Math.fround((( ~ (Math.hypot(( + (y ^ x)), ((x | 0) ? ( + 0x080000000) : ((y % y) | 0))) | 0)) | 0)) != Math.fround(-0x0ffffffff))) >> (Math.max((Math.log10(( + Math.sqrt(2**53+2))) | 0), ((Math.atanh(Math) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-209835301*/count=960; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    switch (((((-0x8000000) ? (0xfe6c2786) : (0xb994603b))-(i1))|0)) {\n      case -3:\n        (Float32ArrayView[((i0)) >> 2]) = (((((i1) ? ((~((0xd8b56000)-(0x4930660a)-(0x2ce69404)))) : ((((-0x8000000)-(-0x20d561c)-(-0x8000000)) ^ ((0x7673e23b)+(0x20449ce9)))))+(i0)) >> (-0x4aa5b*(i0))));\n        break;\n      default:\n        {\n          {\n            i1 = (i1);\n          }\n        }\n    }\n    {\n      return +((new Function( /x/g  **  '' , 9)));\n    }\n    return +((+(((((i1)+(i1)))*-0xab063) | ((i0)+(i1)))));\n    {\n      i1 = ((abs((abs((0x4c3e2db5))|0))|0) < (~((Uint16ArrayView[0]))));\n    }\n    i0 = (i0);\n    i1 = ((i1) ? ((((i1)-(i1)+((((-0x8000000))>>>((-0x8000000)))))>>>(((((0x9e062b5)) >> ((0xea91e2e5))) > (((0x81a7e88d)) & ((-0x8000000))))*0x751b))) : (0xfc3b2bb2));\n    i0 = (i1);\n    i0 = (i0);\n    switch ((0xc950ce7)) {\n      case -2:\n        {\n          {\n            {\n              i1 = (i1);\n            }\n          }\n        }\n        break;\n    }\n    (Int32ArrayView[(((0x245ccd50) != (0x719fab9))+(i1)-(i0)) >> 2]) = ((i1));\n    return +((562949953421313.0));\n    i1 = (i1);\n    return +((-((+((7.737125245533627e+25))))));\n  }\n  return f; })(this, {ff: function shapeyConstructor(gstlpg){\"use strict\"; return this; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[-Infinity, arguments, x, x, arguments, -Infinity, arguments, -Infinity, -Infinity, x, arguments, x, -Infinity, -Infinity, arguments, x, x, arguments, x, arguments, x, -Infinity, -Infinity]); ");
/*fuzzSeed-209835301*/count=961; tryItOut("\"use strict\"; s0 = new String(e0);");
/*fuzzSeed-209835301*/count=962; tryItOut("this.e2.valueOf = Math.cosh.bind(i0);");
/*fuzzSeed-209835301*/count=963; tryItOut("\"use strict\"; (+/*UUV2*/(eval.getMilliseconds = eval.clear));");
/*fuzzSeed-209835301*/count=964; tryItOut("testMathyFunction(mathy0, /*MARR*/[new Boolean(true), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, x, Infinity, Infinity, Infinity, new Boolean(true), Infinity, Infinity, new Boolean(true), new Boolean(true), new Boolean(true), Infinity, new Boolean(true), Infinity, Infinity, x, x, x]); ");
/*fuzzSeed-209835301*/count=965; tryItOut("testMathyFunction(mathy4, [(new String('')), 0, '0', null, (new Boolean(true)), 0.1, objectEmulatingUndefined(), '/0/', ({valueOf:function(){return '0';}}), [], NaN, (new Number(0)), '\\0', 1, (function(){return 0;}), undefined, true, [0], '', ({toString:function(){return '0';}}), (new Boolean(false)), ({valueOf:function(){return 0;}}), false, -0, /0/, (new Number(-0))]); ");
/*fuzzSeed-209835301*/count=966; tryItOut("arguments.callee.caller/*iii*/b = \u3056;let(y = NaN, qipmrb, ahzjlw, kvkdbn, a, kkwgij) { for (var v of s1) { try { /*RXUB*/var r = r2; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\"; print(r.exec(s));  } catch(e0) { } try { i2.send(e0); } catch(e1) { } a1.pop(); }}");
/*fuzzSeed-209835301*/count=967; tryItOut("\"use strict\"; v0 = a0.length;");
/*fuzzSeed-209835301*/count=968; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.imul((Math.fround(Math.log10((Math.fround(Math.clz32((-0x080000001 >>> 0))) === ( - x)))) * ( + ((( + mathy2((y | 0), ( + ( + ( + ((2**53 , y) >>> 0)))))) % Math.sin(y)) | 0))), Math.log10((( ! ((( + ( ! ( + -Number.MAX_SAFE_INTEGER))) || Math.acosh(y)) | 0)) | 0))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -0x080000001, 0.000000000000001, Number.MIN_VALUE, 0/0, -(2**53+2), 2**53, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -(2**53-2), -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0, 0x100000000, 2**53-2, 0x0ffffffff, -0x080000000, Math.PI, -0x100000001, 0x080000000, 0x100000001, -(2**53), 42, -Number.MAX_VALUE, 1, -0x100000000, 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, -0]); ");
/*fuzzSeed-209835301*/count=969; tryItOut(";");
/*fuzzSeed-209835301*/count=970; tryItOut("let e = eval(\"a0.pop(o1, g2.e0);\", x);selectforgc(g2.o0);");
/*fuzzSeed-209835301*/count=971; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy0, [2**53-2, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, -0x07fffffff, -0x080000001, 0x07fffffff, -(2**53), -0, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, 1/0, -(2**53+2), 1.7976931348623157e308, -1/0, 0x0ffffffff, -0x0ffffffff, 0/0, Number.MIN_VALUE, -0x080000000, 0x080000001, 1, 0.000000000000001, -Number.MAX_VALUE, Math.PI, 2**53]); ");
/*fuzzSeed-209835301*/count=972; tryItOut("{g2.offThreadCompileScript(\"function f1(b2) \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    return ((-0x5da78*(i2)))|0;\\n  }\\n  return f;\");\nprint(x);\n/*ADP-2*/Object.defineProperty(a0, 10, { configurable: (x % 9 != 2), enumerable: false, get: f1, set: f0 }); }");
/*fuzzSeed-209835301*/count=973; tryItOut("mathy0 = (function(x, y) { return (((Math.fround(Math.tan(Math.fround((((Math.fround(Math.cosh(Math.tan(( + x)))) | 0) - (Math.log10((( + y) >>> 0)) | 0)) | 0)))) >>> 0) & (Math.imul((Math.max(Math.imul(( ! Math.fround(Math.asin(Math.fround(Number.MIN_VALUE)))), (Math.asinh(Number.MIN_VALUE) & y)), y) | 0), (Math.expm1((Math.expm1((-(2**53) | Math.PI)) >>> 0)) >>> 0)) | 0)) >>> 0); }); testMathyFunction(mathy0, [0.1, (new Boolean(false)), '/0/', [0], objectEmulatingUndefined(), '', (new Boolean(true)), NaN, (function(){return 0;}), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), true, 1, [], (new String('')), undefined, 0, (new Number(-0)), null, '\\0', /0/, (new Number(0)), ({valueOf:function(){return 0;}}), false, -0, '0']); ");
/*fuzzSeed-209835301*/count=974; tryItOut("Object.defineProperty(this, \"g1.v2\", { configurable: false, enumerable: (4277),  get: function() {  return t1.BYTES_PER_ELEMENT; } });");
/*fuzzSeed-209835301*/count=975; tryItOut("m2.delete(g0.f0);");
/*fuzzSeed-209835301*/count=976; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( - ((Math.trunc(x) | 0) !== 1/0)) * (((Math.atan(( + ( - ( + y)))) | 0) ^ (Math.fround(( - Math.fround(x))) | 0)) | 0)); }); testMathyFunction(mathy4, [Math.PI, Number.MAX_VALUE, 0x100000001, -0, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -(2**53), 2**53+2, 42, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 2**53, 1, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, 2**53-2, 0x0ffffffff, 0, 0x080000000, -(2**53-2), 0x100000000, 1.7976931348623157e308, -(2**53+2), 0x07fffffff, 0/0, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=977; tryItOut("\"use strict\"; /*infloop*/for((w) in ((((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: SyntaxError.prototype.toString, }; })).bind)(x)))Array.prototype.unshift.call(g2.a1, g2.o2, t0, t0);");
/*fuzzSeed-209835301*/count=978; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( ! Math.fround(Math.max((( - (( ! (-0x080000000 | 0)) | 0)) | 0), (Math.sin(( + (( + x) || ( + Math.tanh(Math.log10(x)))))) >>> 0))))); }); testMathyFunction(mathy2, [true, [0], (new Boolean(false)), false, -0, 1, '/0/', '', ({valueOf:function(){return 0;}}), [], null, undefined, (function(){return 0;}), 0.1, '0', '\\0', NaN, (new Number(-0)), /0/, objectEmulatingUndefined(), (new String('')), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Number(0)), (new Boolean(true)), 0]); ");
/*fuzzSeed-209835301*/count=979; tryItOut("const f0 = Proxy.createFunction(h1, f1, f2);");
/*fuzzSeed-209835301*/count=980; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return ( - (Math.imul(Math.cos(Math.max(y, x)), (Math.pow((Math.atan2((y ? x : Math.fround((( + 2**53+2) >> Math.fround(x)))), ( + Math.max(( + x), ( + y)))) >>> 0), (( + Math.exp(((( ! (Math.log10(x) >>> 0)) >>> 0) | 0))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [2**53-2, -0x100000000, -0, 42, 1.7976931348623157e308, 0/0, 1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 0, 0x07fffffff, Number.MAX_VALUE, -0x100000001, -0x07fffffff, -(2**53), 2**53+2, 0x100000001, 0x0ffffffff, 0x080000001, -0x080000001, 1, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, -0x080000000, Math.PI, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=981; tryItOut("mathy2 = (function(x, y) { return (Math.max(Math.fround((Math.fround(( - Math.imul(Math.sqrt(y), ( + ( + Math.exp(( + y))))))) < (mathy0(Math.fround(((Math.acos((x | 0)) | 0) ** ((( + -0x0ffffffff) !== Math.ceil(y)) | 0))), ( + ( ~ ( + ((x ^ x) | 0))))) | 0))), ( + Math.cbrt(Math.fround((( - Math.fround(( + ( ! ( + y))))) >>> 0))))) | 0); }); testMathyFunction(mathy2, [1, 0/0, 0x0ffffffff, 0x100000001, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 42, -0x080000001, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, 0x080000000, -(2**53), 0x100000000, Math.PI, -1/0, 2**53+2, 0, -0, -0x100000001, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 0.000000000000001, -(2**53+2), 2**53, 2**53-2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=982; tryItOut("mathy3 = (function(x, y) { return ( + Math.sign(( ! (( - ((( ~ ((( + (x >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0)))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), [], '', -0, ({toString:function(){return '0';}}), (new Number(0)), '0', 0.1, [0], '/0/', ({valueOf:function(){return 0;}}), 0, (new String('')), (new Boolean(true)), /0/, false, NaN, 1, '\\0', undefined, true, (function(){return 0;}), objectEmulatingUndefined(), (new Boolean(false)), (new Number(-0)), null]); ");
/*fuzzSeed-209835301*/count=983; tryItOut("mathy2 = (function(x, y) { return Math.tan(Math.fround(mathy1(Math.fround(( + Math.hypot(( + y), ( + Math.hypot(Math.fround(0x100000000), Math.fround(x)))))), Math.fround(mathy0((-Number.MIN_VALUE - (((((y >>> 0) >> 2**53+2) >>> 0) + x) | 0)), ( ~ x)))))); }); testMathyFunction(mathy2, [-0, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0, Number.MAX_VALUE, -Number.MAX_VALUE, 42, 1, 0x0ffffffff, 0x07fffffff, 2**53+2, -0x0ffffffff, 1/0, -1/0, -0x100000000, 0x080000000, -(2**53), 2**53-2, 2**53, 0x100000001, 0/0, Math.PI, 0x080000001, -0x080000000, 0.000000000000001, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=984; tryItOut("g0.m1.get(m0);");
/*fuzzSeed-209835301*/count=985; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=986; tryItOut("mathy0 = (function(x, y) { return Math.atan2(( + ((Math.log10(Math.atanh(y)) >>> 0) ? ( + ( + Math.round(( + (( + (( + 0x100000001) ? x : ( + y))) - y))))) : (Math.asinh(( - ((-Number.MIN_VALUE , Math.cos(1)) >>> 0))) >>> 0))), (( + Math.min(( + y), ( + y))) ? ( + Math.log(Math.fround((Math.fround((Math.trunc((y | 0)) | 0)) >>> Math.fround(( + x)))))) : ( + Math.log2(Math.fround((y === (Math.fround(Math.imul(Math.fround(y), Math.fround(y))) >= Math.max(( ! 0x07fffffff), -Number.MIN_SAFE_INTEGER)))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, 2**53, -0, 0x080000001, 0x0ffffffff, 0.000000000000001, -(2**53+2), 0/0, 2**53-2, -(2**53), 2**53+2, 1/0, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, -0x080000000, -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, 0x07fffffff, -0x100000001, -0x07fffffff, 0, 1, -0x100000000, 1.7976931348623157e308, -(2**53-2), -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=987; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( - (( - y) ? ((( + ( ! (( + -Number.MIN_SAFE_INTEGER) & Math.atan2(( + 0x080000000), y)))) ? (((((Math.imul((x >>> 0), (x | 0)) >>> 0) - x) != Math.PI) | 0) ? x : (-0 == (Math.imul((x >>> 0), mathy1(x, -Number.MIN_SAFE_INTEGER)) | 0))) : y) | 0) : (Math.max(Math.sqrt((mathy2((( ! x) >>> 0), mathy2(y, 1)) | 0)), ( - y)) !== ( - (Math.atan2((Math.hypot((Math.tanh(0x080000000) >>> 0), y) >>> 0), (Math.fround((Math.fround(y) ? (Math.sin(y) >>> 0) : Math.fround(Math.fround((y & x))))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, 0.000000000000001, 42, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0x0ffffffff, -0, 0, 2**53, -0x100000000, -0x100000001, 0x080000001, -0x080000000, 0x080000000, -(2**53), Math.PI, -0x0ffffffff, -Number.MAX_VALUE, 0/0, Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -1/0, 0x100000000, -(2**53+2), 0x07fffffff, -0x080000001, 1]); ");
/*fuzzSeed-209835301*/count=988; tryItOut("mathy1 = (function(x, y) { return ( + Math.log2(( + Math.cbrt((Math.max(Math.hypot(Math.imul(( + Math.cbrt(( + x))), -(2**53)), (( ~ x) >>> 0)), ( - ((( ~ (x | 0)) | 0) >>> 0))) | 0))))); }); testMathyFunction(mathy1, [-0x100000000, 2**53-2, Math.PI, 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0x080000001, -0x080000001, 0, -0x0ffffffff, 0x100000001, 0x080000000, 42, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 1, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_VALUE, 1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, -(2**53+2), -Number.MIN_VALUE, 1.7976931348623157e308, -0, -(2**53-2), 2**53, -0x100000001]); ");
/*fuzzSeed-209835301*/count=989; tryItOut("{throw  /x/ ;v2 = t1.byteOffset; }");
/*fuzzSeed-209835301*/count=990; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy1((( ! ( + (Math.max(mathy1((Math.pow(x, ( + x)) | 0), (y | 0)), ( ! 0.000000000000001)) >>> 0))) >>> (mathy1((Math.fround(Math.atan2(Math.fround(y), Math.fround(( + (( + (( + mathy0((y | 0), ( + y))) ** Math.fround(x))) >>> ( + Number.MIN_SAFE_INTEGER)))))) >>> 0), ((Math.round((((-Number.MAX_SAFE_INTEGER >>> 0) | x) >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.fround(( + Math.fround(mathy1(Math.fround(Math.cos(( + (y || x)))), (x | 0)))))); }); testMathyFunction(mathy2, [0.000000000000001, Math.PI, -0x080000000, 1, 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), 1/0, 42, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, Number.MAX_VALUE, 0, 0x080000000, -0x100000000, -0x100000001, 0x07fffffff, 1.7976931348623157e308, -(2**53), 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, 2**53+2, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-209835301*/count=991; tryItOut("\"use asm\"; var pcvzmr = new ArrayBuffer(24); var pcvzmr_0 = new Uint32Array(pcvzmr); pcvzmr_0[0] =  \"\" ; var pcvzmr_1 = new Int32Array(pcvzmr); pcvzmr_1[0] = 8; print(timeout(1800));");
/*fuzzSeed-209835301*/count=992; tryItOut("let (d) { g0.m1.has((4277)); }");
/*fuzzSeed-209835301*/count=993; tryItOut("v0 = t0.byteOffset;");
/*fuzzSeed-209835301*/count=994; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(( + (Math.max(((( + (((-0x100000001 >>> 0) / (( ~ x) >>> 0)) >>> 0)) | (Math.min((x >>> 0), (x >>> 0)) >>> 0)) | 0), (((( ! (( + Math.fround(((-0 >>> 0) | 0x100000001))) >>> 0)) | 0) >>> 0) % (y >>> 0))) | 0)), Math.imul((Math.fround(Math.cbrt(Math.fround(Math.imul(Math.sqrt(x), ( ~ 1.7976931348623157e308))))) | 0), Math.max(( + x), Math.fround(((Math.atan2(x, ( + Math.imul(( + Math.atan2(x, (x >>> 0))), ( + Math.atan2(x, x))))) | 0) || (y >>> 0)))))); }); testMathyFunction(mathy0, [0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, 42, -Number.MIN_VALUE, 0x080000001, 0x100000000, 0, 0x07fffffff, 2**53, -(2**53+2), 1, -0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 0x100000001, -0x0ffffffff, 0x0ffffffff, -0, -0x080000000, -Number.MAX_VALUE, Math.PI, -(2**53-2), Number.MIN_VALUE, 2**53+2, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, Number.MAX_VALUE, 0/0, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=995; tryItOut("\"use strict\"; print(x);function x(y)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -67108865.0;\n    i1 = (i1);\n    (Float64ArrayView[((i1)) >> 3]) = ((1.0));\n    {\n      {\n        (Float32ArrayView[((i1)) >> 2]) = ((d0));\n      }\n    }\n    return ((-0xaaf0c*(i1)))|0;\n  }\n  return f;Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-209835301*/count=996; tryItOut("v1 = g0.eval(\"function f0(v1)  { \\\"use strict\\\"; var yqpuyd = new ArrayBuffer(6); var yqpuyd_0 = new Float32Array(yqpuyd); yqpuyd_0[0] = 14; print(Math.min(\\\"\\\\uF382\\\", true)); } \");");
/*fuzzSeed-209835301*/count=997; tryItOut("s0.valueOf = (function(j) { if (j) { try { /*MXX1*/o1 = g0.Number.MAX_VALUE; } catch(e0) { } try { for (var p in o1.a2) { try { v1 = (i1 instanceof h0); } catch(e0) { } try { v2 = (m1 instanceof i1); } catch(e1) { } try { a1 = Array.prototype.slice.call(g2.a1, s2); } catch(e2) { } e2.has(a0); } } catch(e1) { } try { b2 + ''; } catch(e2) { } /*MXX2*/g2.Map.name = h2; } else { try { v2 = t1.length; } catch(e0) { } try { ; } catch(e1) { } s1 += 'x'; } });");
/*fuzzSeed-209835301*/count=998; tryItOut("/*oLoop*/for (var egdvvm = 0; egdvvm < 41; ++egdvvm) { a1 = r1.exec(s0); } ");
/*fuzzSeed-209835301*/count=999; tryItOut("\"use strict\"; e0.add(m0);");
/*fuzzSeed-209835301*/count=1000; tryItOut("\"use strict\"; o2.v0 = (this.s2 instanceof b2);");
/*fuzzSeed-209835301*/count=1001; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=1002; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (((((Math.tanh((-Number.MIN_VALUE | 0)) | 0) | 0) + ((( ! ((Math.pow((-0x100000000 >>> 0), (y >>> 0)) >>> 0) >>> 0)) % ( + ( ~ ( + ( + Math.imul(0/0, ( + -Number.MAX_SAFE_INTEGER))))))) | 0)) | 0) == ( + ( + ( + ((Math.pow((x | 0), (x | 0)) | 0) + (((x < 0/0) | 0) > (-1/0 ** (x >>> 0)))))))); }); ");
/*fuzzSeed-209835301*/count=1003; tryItOut("testMathyFunction(mathy4, [-1/0, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 1, 2**53-2, -(2**53-2), 0x100000001, 0x0ffffffff, 2**53+2, 0, 0x100000000, 42, 1/0, 0x07fffffff, -0x080000001, 0/0, -Number.MAX_VALUE, 0x080000000, -0, -0x100000001, -Number.MIN_VALUE, 2**53, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=1004; tryItOut("{/*iii*//*infloop*/do {for (var p in t1) { Array.prototype.pop.apply(a0, []); }/*RXUE*//(?:\\cR[^]{1,3}|(?!(?=\\f?)))|^(?!\\d(?=^+))\\2+|(?=(?![\\u000b-\\v-\u0083\\n\\x02])|[^]+?)+?/yim.exec(\"\\ua408\\u00fd\\u00ed?D\\n\\n\\u3a09\\u000c\\n\\n\\u00a2\\u0013\\n\"); } while(x);/*hhh*/function zjaeyg(\u3056){Object.preventExtensions(g1);}e1.add(v1); }");
/*fuzzSeed-209835301*/count=1005; tryItOut("\"use strict\"; if(true) a1.sort((function mcc_() { var ljwrxi = 0; return function() { ++ljwrxi; f1(/*ICCD*/ljwrxi % 10 == 4);};})(), m2, b0);\nprint(x);\n else  if ((function shapeyConstructor(cobopw){this[2] = q => q;this[\"toSource\"] =  '' ;return this; })( /x/ , new RegExp(\"\\\\2\", \"gm\"))) neuter(o2.b1, \"change-data\"); else {print(this);t0 = new Float32Array(15); }");
/*fuzzSeed-209835301*/count=1006; tryItOut("g1.m0.set(((void shapeOf(x))((new /\\B*?/gm ?  /x/g  : /^{3,3}|((?:(?![^]))+){65537,}/gyim((9.throw(\"\\u55C8\")),  \"\" )))), v1);");
/*fuzzSeed-209835301*/count=1007; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.pow(( + Math.log1p(( + Math.hypot(Math.min(42, (x === Math.max(( + y), x))), 2**53)))), ((2**53-2 === ( + Math.pow(0.000000000000001, Math.log10(x)))) | 0)) <= Math.round(( + mathy0((x ? Math.log((Math.imul((x >>> 0), Math.fround(y)) | 0)) : Math.log1p(y)), (Math.fround(Math.acosh(Math.fround(((0x07fffffff << ((Math.clz32((-0x0ffffffff >>> 0)) >>> 0) >>> 0)) >>> 0)))) >>> 0))))); }); testMathyFunction(mathy4, [undefined, false, (new Boolean(false)), (new Number(0)), null, -0, 0.1, (new String('')), [0], '\\0', '0', objectEmulatingUndefined(), (new Boolean(true)), /0/, [], 0, '/0/', true, (function(){return 0;}), (new Number(-0)), 1, NaN, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '']); ");
/*fuzzSeed-209835301*/count=1008; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(([^\\\\f-\\\\cZ\\\\s\\\\S\\\\x43-\\\\xB0]*?))\\\\2[^\\u453e-\\\\u9E8d\\\\u0059]+?\\\\u0C1E{2,3}*\", \"gim\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=1009; tryItOut("Object.prototype.watch.call(a2, \"caller\", (function() { o0.v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 != 0), noScriptRval: true, sourceIsLazy: true, catchTermination: false })); return p2; }));");
/*fuzzSeed-209835301*/count=1010; tryItOut("\"use strict\"; v1 = a2.reduce, reduceRight(f0, g1, g0.b1);");
/*fuzzSeed-209835301*/count=1011; tryItOut("g1.v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (new RegExp(\"\\\\2(?:[^])|\\\\d?\", \"gym\") = ({a2:z2}))(), sourceIsLazy: true, catchTermination: x }));");
/*fuzzSeed-209835301*/count=1012; tryItOut("\"use asm\"; /*infloop*/M:for(let Array in window) {v0 = Object.prototype.isPrototypeOf.call(h0, f0);print(/(?:(?!\\b)|[^]+?^|\\s+)|[\u009e-\\u1de4\\d\\s\\cB-\\t]/gi); }");
/*fuzzSeed-209835301*/count=1013; tryItOut("\"use strict\"; for (var p in b0) { try { h1 + m1; } catch(e0) { } try { ; } catch(e1) { } a0 = new Array; }");
/*fuzzSeed-209835301*/count=1014; tryItOut("print(uneval(g0.o0));");
/*fuzzSeed-209835301*/count=1015; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul((mathy1((1/0 ? (mathy1(y, ((Math.max(new RegExp(\"(?:(?:[^]\\\\w+?))?|((?:[^\\\\b\\\\u5b94]))+?[^]{1,}\", \"i\"), ((Math.max(( + (Math.fround(Number.MAX_SAFE_INTEGER) | y)), y) >>> 0) >>> 0)) >>> 0) | 0)) | 0) : ((Math.pow(( + x), Math.max(Math.max(x, x), (Math.ceil(x) | 0))) >>> 0) >>> 0)), ( + Math.imul(0x100000000, ( + ( + Math.tanh(x)))))) >>> 0), mathy0(( + (( + ( + Math.min(( + ((y | 0) % Math.fround(mathy1(Math.fround((x , y)), -Number.MAX_VALUE)))), ( + (((Number.MIN_VALUE >>> 0) | ((( - (y >>> 0)) >>> 0) >>> 0)) == (x | 0)))))) && ( + (Math.pow((Math.cos((Math.atan((y | 0)) | 0)) | 0), ( ! x)) | 0)))), (( - Math.clz32(0x080000001)) >>> 0))) | 0); }); ");
/*fuzzSeed-209835301*/count=1016; tryItOut("for (var p in g0) { try { e0.has(v2); } catch(e0) { } try { e1.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = a11 + 7; var r1 = 0 + r0; var r2 = a1 - 6; var r3 = a8 & a7; var r4 = a9 & a11; var r5 = r4 | a4; a10 = 7 + a8; var r6 = a11 ^ a10; var r7 = a4 % 4; var r8 = a11 / a7; var r9 = a7 + 4; var r10 = 3 ^ a4; var r11 = x - 9; a7 = a12 - r4; a7 = a7 % 9; var r12 = a0 % r5; var r13 = 4 * r9; var r14 = r2 | r9; return a11; }); } catch(e1) { } try { selectforgc(o0); } catch(e2) { } m1 = new WeakMap; }");
/*fuzzSeed-209835301*/count=1017; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ((( - Math.fround(( + Math.fround(( - 2**53-2))))) >>> 0) || ((Math.fround(( - (Math.log2((Math.fround(Math.atan2((Math.sinh(y) >>> 0), Math.fround(Math.fround((42 * Math.fround(Math.fround(( ! Math.fround(y))))))))) >>> 0)) >>> 0))) !== Math.imul(( + ( ! ( + y))), ( + Math.abs(Math.acos(y))))) >>> 0))); }); testMathyFunction(mathy0, [0x0ffffffff, -0x080000000, -1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, Math.PI, 0x100000001, -0x100000001, 0, -Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, 1, 2**53-2, Number.MAX_VALUE, 0x080000000, 2**53+2, -0x080000001, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, -(2**53), -0x0ffffffff, -(2**53+2), 0x080000001, 42, -0, 1/0]); ");
/*fuzzSeed-209835301*/count=1018; tryItOut("testMathyFunction(mathy3, [-Number.MIN_VALUE, Number.MIN_VALUE, 0x0ffffffff, -0x100000000, -0x080000000, 42, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, 2**53-2, -0, -Number.MAX_VALUE, -(2**53+2), Math.PI, Number.MAX_VALUE, -(2**53-2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, 1/0, 2**53, -1/0, 0/0, -(2**53), 0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0, 2**53+2, 1, Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-209835301*/count=1019; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.max(Math.fround(( + mathy0((( - ( + x)) >>> 0), ( ! ((y / x) | 0))))), ( + Math.pow(Math.max(Math.fround((Math.imul((( + (x > ( + x))) | 0), (( + ( + ((y || x) >>> 0))) | 0)) | 0)), x), ( ! ( + Math.imul(( ! y), ( + (y + x))))))))); }); testMathyFunction(mathy5, [0x080000000, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, Math.PI, 0/0, -Number.MAX_VALUE, 0, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -(2**53+2), -(2**53), -0x100000000, -0, 1, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, 0x100000001, 42, Number.MAX_VALUE, -0x080000001, -0x07fffffff, -1/0, 0x080000001]); ");
/*fuzzSeed-209835301*/count=1020; tryItOut("/*infloop*/for(var delete a. .__proto__ in ((/*wrap3*/(function(){ var ajtxei = x--; (Map.prototype.keys)(); }))(eval(\"\\\"use asm\\\"; print(allocationMarker());\")))){var cvnjvp = new ArrayBuffer(0); var cvnjvp_0 = new Uint16Array(cvnjvp); print(cvnjvp_0[0]); cvnjvp_0[0] = 15;  \"\" ; }");
/*fuzzSeed-209835301*/count=1021; tryItOut("Array.prototype.pop.apply(a1, [o0]);");
/*fuzzSeed-209835301*/count=1022; tryItOut("/*iii*/v0 = g0.eval(\"function f2(g1)  { \\\"use strict\\\"; return this } \");/*hhh*/function gonwda\u000c(){/*MXX1*/o0 = o1.o2.g0.URIError.prototype.message;}");
/*fuzzSeed-209835301*/count=1023; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1024; tryItOut("if(true) {h1.keys = f2; }");
/*fuzzSeed-209835301*/count=1025; tryItOut("\"use strict\"; yield x;x.stack;");
/*fuzzSeed-209835301*/count=1026; tryItOut("print(m1);");
/*fuzzSeed-209835301*/count=1027; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    (Uint8ArrayView[((imul(((((0xff96ed8d)) << ((0xeceeecf7)))), (!(i3)))|0) / (~(((((0xfafb9548)) & ((0xfc711ed9))) > (((0x686470a0)) | ((0xffffffff))))))) >> 0]) = (((0x133a9211)));\n    return (((i0)-(i3)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0/0, -0x0ffffffff, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, 0.000000000000001, 0, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, -Number.MAX_VALUE, 0x07fffffff, -(2**53), -0x07fffffff, 0x080000001, Math.PI, Number.MAX_VALUE, 2**53+2, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0, 1/0, -Number.MAX_SAFE_INTEGER, 1, -0x100000001]); ");
/*fuzzSeed-209835301*/count=1028; tryItOut("if((x % 53 == 49)) {print( '' );g0.a1 = t2[9]; }");
/*fuzzSeed-209835301*/count=1029; tryItOut("v1 = o1.s1[\"pop\"];");
/*fuzzSeed-209835301*/count=1030; tryItOut("yield x;this.zzz.zzz;");
/*fuzzSeed-209835301*/count=1031; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.atan2(((((x | 0) + (Math.max(x, (( ~ (-0x100000000 >>> 0)) >>> 0)) >>> 0)) >>> 0) >>> 0), (Math.clz32(Math.asin(x)) >>> 0)) >>> 0) && Math.min(mathy1(((mathy1(-Number.MIN_SAFE_INTEGER, x) >>> 0/0) - Math.fround((( + Math.max(( + (y >>> x)), y)) % (x >>> 0)))), (Math.fround(( ! Math.fround(( - Math.fround(Math.min(y, x)))))) >>> 0)), ( + (((x | 0) | (Math.abs(y) | 0)) >>> 0)))); }); ");
/*fuzzSeed-209835301*/count=1032; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?:[^])+)(?=(?=\\1))+?\\x13{2,3}|\\W{0,}?/gyi; var s = \"\\n\\n\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-209835301*/count=1033; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul(Math.fround((Math.fround(Math.imul((x | 0), (Math.asinh(Math.fround((0x100000001 ^ y))) | 0))) << Math.fround(Math.min(Math.fround(y), Math.fround(mathy1(( ~ x), x)))))), (Math.exp(Math.tanh(y)) << ( + x))); }); testMathyFunction(mathy2, [1, 0/0, -Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 2**53+2, -0, -0x100000001, 2**53-2, Number.MIN_VALUE, -0x080000000, 0.000000000000001, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, -1/0, 0x0ffffffff, 0x080000001, 1.7976931348623157e308, 1/0, 0x080000000, 2**53, -Number.MIN_VALUE, 0, -(2**53), -(2**53+2), Number.MAX_VALUE, -(2**53-2), -0x080000001]); ");
/*fuzzSeed-209835301*/count=1034; tryItOut("a1.sort((function(j) { if (j) { try { m0 = new Map; } catch(e0) { } const this.s0 = ''; } else { try { g1.h0 = a1[11]; } catch(e0) { } try { g2.v2 = true; } catch(e1) { } this.g0.s1 += 'x'; } }), e0, this.s0);");
/*fuzzSeed-209835301*/count=1035; tryItOut("mathy0 = (function(x, y) { return Math.hypot(( ~ ( + Math.tan(( + (Math.pow(Math.fround(( + (( + (((x >>> 0) == x) >>> 0)) & ( + y)))), -Number.MIN_SAFE_INTEGER) | 0))))), (Math.hypot((( + Math.atan2(Math.imul(( + y), x), Math.fround(( ! Math.cos(Math.min(x, -0)))))) >>> 0), ((Math.sin(Math.atanh(y)) | 0) | 0)) >>> 0)); }); testMathyFunction(mathy0, [1, 0x100000001, 1.7976931348623157e308, 1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -0x080000000, 2**53, 0x07fffffff, -(2**53-2), 0x080000001, 0, -(2**53+2), 0x080000000, Number.MIN_VALUE, 42, -0x07fffffff, 0x0ffffffff, 2**53+2, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, -0x100000000, -0]); ");
/*fuzzSeed-209835301*/count=1036; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((( - ( + (( - ((( ! x) >>> 0) == (Math.max((-0x0ffffffff >>> 0), (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) >>> 0))) | 0) >>> 0) ? ( + (( + (( - y) | 0)) ? ( + (( + Math.hypot(y, ((-0x100000001 ? ( + (( + -0x080000001) ? -0x100000001 : ( + y))) : (x | y)) | 0))) >> (((((((Math.sinh((x >>> 0)) >>> 0) >>> 0) | (x >>> 0)) >>> 0) / ((Math.pow((x >>> 0), Math.log2(mathy0((y | 0), 1/0))) >>> 0) >>> 0)) >>> 0) >>> 0))) : ( + ((Math.sqrt((x + y)) !== Math.log(( + (Math.fround(((x >>> 0) == Math.fround(Math.atan2((y | 0), ( + x))))) == -0x100000000)))) | 0)))) : (( ~ Math.atan2(y, y)) >= Math.fround((((( + y) != (x | 0)) | 0) ? ((( + (Math.atan2(x, ( + Math.sign(( + y)))) >>> 0)) >>> 0) >>> 0) : mathy0(( + y), (2**53-2 ? Math.atan2(y, y) : (( ! x) >>> 0))))))); }); ");
/*fuzzSeed-209835301*/count=1037; tryItOut("m1.set(new (true([]))(), this.p2);");
/*fuzzSeed-209835301*/count=1038; tryItOut("g2.o2.f0.valueOf = (function mcc_() { var yxluik = 0; return function() { ++yxluik; if (/*ICCD*/yxluik % 3 == 1) { dumpln('hit!'); v1 = this.b2.byteLength; } else { dumpln('miss!'); try { f1 = Proxy.createFunction(h0, f2, f1); } catch(e0) { } try { v0 = g1.eval(\"\\\"use strict\\\"; /*RXUB*/var r = /((?=[\\\\D\\\\xd8-\\u57bb\\\\\\u00ad\\\\cF-\\\\u5Af5]|\\\\2)|(?!\\\\S$+?){4,5}|(?=\\\\s(\\\\W)+{1,})|(?!(?:[])))|(\\\\1\\\\3)[^]{2}(?:\\\\B.){0,4}(\\\\W)|\\\\cG{4,6}/i; var s = \\\"\\\\u5bb4_0\\\\n\\\\n\\\\u0007\\\\n\\\\u000700\\\\n\\\\n\\\\n\\\\u9ebd\\\\u6410\\\\n0\\\"; print(s.match(r)); print(r.lastIndex); \"); } catch(e1) { } try { a1 = r0.exec(s2); } catch(e2) { } for (var v of v0) { try { h1.defineProperty = f1; } catch(e0) { } try { Array.prototype.shift.call(a2); } catch(e1) { } try { e0.has(m2); } catch(e2) { } i0.send(f0); } } };})();");
/*fuzzSeed-209835301*/count=1039; tryItOut("/*oLoop*/for (var vfkdou = 0; vfkdou < 106; ++vfkdou) { f0 + this.g2; } ");
/*fuzzSeed-209835301*/count=1040; tryItOut("for (var p in t1) { Array.prototype.splice.call(this.a0, 7, 6, b0); }");
/*fuzzSeed-209835301*/count=1041; tryItOut("mathy2 = (function(x, y) { return ((Math.sign((( + Math.fround(-0x100000001)) >>> 0)) | 0) !== Math.pow(((x >>> 0) !== ( + Math.fround(mathy0(-(2**53), Math.pow(Math.fround((y !== x)), -Number.MAX_VALUE))))), ((0/0 - (-Number.MAX_VALUE >>> 0)) >>> 0))); }); ");
/*fuzzSeed-209835301*/count=1042; tryItOut("\"use strict\"; yield (/*FARR*/[[[]].__defineSetter__(\"w\", x), .../*FARR*/[]].some(arguments.callee.caller.caller.caller.caller.caller,  \"\"  >>>= \"\\u12C2\"));with({}) x.fileName;");
/*fuzzSeed-209835301*/count=1043; tryItOut("\"use strict\"; while((Math.imul((((void options('strict_mode'))) instanceof /*RXUE*/new RegExp(\"\\\\d(.)*?|\\\\B[\\\\B\\\\W\\\\xd5-\\\\u1AE1]\\\\B|[^]++?{3}\", \"y\").exec(\"0\\u009f\")), window)) && 0)function shapeyConstructor(aqatqu){\"use strict\"; for (var ytqfybhsd in this) { }return this; }/*tLoopC*/for (let b of (function() { yield (x) = new (window = this)(x); } })()) { try{let mpcozg = new shapeyConstructor(b); print('EETT'); for (var p in b1) { try { g2.f1 = Proxy.createFunction(h2, o2.f2, f2); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\"; print(r.exec(s));  } catch(e1) { } o2.v2 = /(?:\\b(\\u4EF4)*|[]{0,3})+/gi; }}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-209835301*/count=1044; tryItOut("h1.set = f2;");
/*fuzzSeed-209835301*/count=1045; tryItOut("mathy4 = (function(x, y) { return  for (++this.zzz.zzz in (makeFinalizeObserver('tenured'))) for (z of Math.atan2( '' , -28)) for (c in this.__defineGetter__(\"eval\", ((void options('strict'))))) for each (y in /*FARR*/[x].sort((window).call, (4277))) for (x of  \"\" ) for (x of /*FARR*/[new RegExp(\"\\\\w\", \"g\"), function ([y]) { }]) for (x in -22) for (x of 12); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -(2**53), -0x080000000, -1/0, Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, 2**53, 2**53+2, -0x100000000, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001, -0, -Number.MIN_VALUE, 0x100000001, Math.PI, 0x07fffffff, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, 0/0, 42, -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, Number.MIN_VALUE, 2**53-2, 0x100000000, 1]); ");
/*fuzzSeed-209835301*/count=1046; tryItOut("v2 = a1.length;");
/*fuzzSeed-209835301*/count=1047; tryItOut("{ void 0; minorgc(true); } a2 = r1.exec(g0.o0.s2);/*infloop*/for(let [] = x; yield (arguments)(); x) {o1.o2.o1.m1.has(v0); }");
/*fuzzSeed-209835301*/count=1048; tryItOut("mathy3 = (function(x, y) { return Math.log10(Math.sinh(Math.fround(( - (( ~ (0x100000001 >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [-0x100000001, 2**53, -(2**53+2), -0x080000001, 0x07fffffff, 1.7976931348623157e308, 0x080000001, 1, -(2**53), Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, -1/0, 0, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 0x080000000, -0x07fffffff, 2**53+2, 1/0, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), Math.PI, 0.000000000000001, -0x100000000, 0/0, 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1049; tryItOut("mathy5 = (function(x, y) { return (Math.fround((Math.imul(( + (( + mathy4((y % (mathy3(Number.MAX_SAFE_INTEGER, y) | 0)), Math.fround((( - ((y > ( ~ x)) | 0)) | 0)))) < ( + Math.cos(x)))), ((Math.log2(( ! (Math.log1p(x) | 0))) >>> 0) & ((( ! ((Math.fround(mathy3(Math.fround(-Number.MIN_SAFE_INTEGER), Math.fround(0/0))) === y) | 0)) >>> 0) >>> 0))) >>> 0)) || Math.atan(Math.acos(( + Math.fround(Math.sin((x >>> 0))))))); }); testMathyFunction(mathy5, [-(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x080000001, 1, Number.MIN_VALUE, 0.000000000000001, -0x100000001, -(2**53+2), 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 1/0, -0, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, Math.PI, 2**53-2, 2**53+2, -0x07fffffff, 0x080000001, 42, -0x080000000, 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1050; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + (((( + mathy3((( + mathy3(( + Math.imul(y, y)), ( + ( + -Number.MIN_SAFE_INTEGER)))) >>> 0), y)) / ( + Math.fround(mathy1(Math.fround(Math.fround((Math.fround(x) < Math.fround(Math.fround(( ~ Math.fround(y))))))), Math.fround(( - y)))))) >>> 0) ? ((mathy2(((Math.pow((y >>> 0), (y >>> 0)) | 0) | 0), ((((Math.fround(Math.abs(( + Math.atan(( + x))))) | 0) * (x | 0)) | 0) | 0)) | 0) >>> 0) : Math.log1p(( ~ (Math.log2(2**53-2) | 0))))); }); testMathyFunction(mathy4, [-0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 0x080000001, -1/0, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0x100000000, 42, 1.7976931348623157e308, 0x100000001, 0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -0, -(2**53-2), 1/0, 2**53-2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000001, 0/0, 0.000000000000001, 1, Number.MIN_VALUE, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1051; tryItOut("mathy4 = (function(x, y) { return (((( ~ ( + Math.log(( + ( + Math.expm1(y)))))) >>> 0) <= Math.max(((y ? ( + Math.atan2(( + (1 && x)), ( + x))) : y) != x), Math.atan2((x < y), Math.abs(x)))) !== Math.round(Math.cbrt((Math.cbrt(Math.fround((y && (y == x)))) >>> 0)))); }); testMathyFunction(mathy4, [-0x07fffffff, -(2**53-2), 0x07fffffff, 1, -(2**53+2), 0x100000001, 2**53-2, -Number.MIN_VALUE, -1/0, 1.7976931348623157e308, -(2**53), Math.PI, -0, 0, -0x080000001, 1/0, -0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0.000000000000001, 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, 42, 2**53+2, 0x080000000, 0/0, Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=1052; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.sqrt(( ~ (( - ( ~ y)) >>> 0))) < ( + Math.expm1(Math.fround(Math.fround(( ~ (x | 0))))))) || Math.fround(( + Math.cbrt(( + Math.sign(((((x | 0) ** (y | 0)) | 0) ? ( + (Math.ceil((x >>> 0)) >>> 0)) : ((( + x) ? ( + 1/0) : ( + y)) >>> 0)))))))); }); testMathyFunction(mathy0, [0, 1/0, 42, -0x100000001, 0x100000001, 0x100000000, Math.PI, 2**53-2, 0x0ffffffff, -1/0, 2**53, -(2**53), Number.MIN_VALUE, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, 0.000000000000001, 0x080000001, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -0x0ffffffff, -0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-209835301*/count=1053; tryItOut("/*tLoop*/for (let y of /*MARR*/[new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), -(2**53-2), new String(''), -(2**53-2)]) { d; }");
/*fuzzSeed-209835301*/count=1054; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1055; tryItOut("testMathyFunction(mathy3, [0x07fffffff, 0, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, Number.MIN_VALUE, 1, 2**53-2, Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -0x080000001, 0x080000000, -0x080000000, 0x080000001, 0x0ffffffff, -(2**53), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 42, -0, 0x100000001, 0/0, -(2**53+2), -0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-209835301*/count=1056; tryItOut("for(let a = new (function(q) { \"use strict\"; return q; })(({a1:1}).__defineSetter__(\"\\u3056\", undefined),  \"\" ) in new RegExp(\"(?=(?:^)|[])|\\\\2|\\ub17c|.+?\", \"g\")) {26; }");
/*fuzzSeed-209835301*/count=1057; tryItOut("for(var y in delete x.NaN) /*vLoop*/for (kbisei = 0; kbisei < 12; ++kbisei) { d = kbisei; \"\\u8027\"; } ");
/*fuzzSeed-209835301*/count=1058; tryItOut("let (x) { Object.defineProperty(this, \"g1\", { configurable: true, enumerable: (x % 6 == 4),  get: function() {  return this; } }); }");
/*fuzzSeed-209835301*/count=1059; tryItOut("for (var p in g1) { try { Object.defineProperty(o2, \"v0\", { configurable: (x % 6 == 2), enumerable: false,  get: function() { g0.a1 = Array.prototype.filter.apply(this.a1, [(function(j) { if (j) { try { (void schedulegc(g0.g2)); } catch(e0) { } t2[5] = b0; } else { try { for (var v of o0.m0) { try { /*ODP-1*/Object.defineProperty(o0, \"expm1\", ({})); } catch(e0) { } try { v0 = o1.r1.flags; } catch(e1) { } try { v1 = evalcx(\"a0[10] = ({a1:1});\", g0); } catch(e2) { } Object.prototype.unwatch.call(this.o1, \"startsWith\"); } } catch(e0) { } e2.has(m1); } }), p2, v0]); return true; } }); } catch(e0) { } /*RXUB*/var r = r2; var s = \"\\u72450\\u7245\\u72450\\u7245\\u7245\\u72450\\u7245\\u72450\\u7245\"; print(uneval(s.match(r))); print(r.lastIndex);  }");
/*fuzzSeed-209835301*/count=1060; tryItOut("s1 += 'x';");
/*fuzzSeed-209835301*/count=1061; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -2097153.0;\n    return ((((i0) ? (/*FFI*/ff()|0) : ((0x2e535694) ? ((~~((-4.835703278458517e+24) + (-34359738369.0)))) : (i0)))-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: this.__defineSetter__(\"x\", runOffThreadScript)}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 2**53, -0x100000000, -(2**53+2), -(2**53), 2**53+2, -0x080000000, Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, 1/0, 0x100000000, 42, 1, 0/0, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, 0x100000001, 0, 0.000000000000001, -0x080000001, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1062; tryItOut("\"use strict\"; v0 = a2.reduce, reduceRight((function(j) { if (j) { try { print(uneval(e0)); } catch(e0) { } try { s1 += s0; } catch(e1) { } try { v0 = evaluate(\"/* no regression tests found */\", ({ global: g0.g0, fileName: null, lineNumber: 42, isRunOnce: (Math.acosh(this.yoyo(window))), noScriptRval: x, sourceIsLazy: false, catchTermination: (x % 52 != 31) })); } catch(e2) { } print(uneval(g1.a2)); } else { try { t2 + b2; } catch(e0) { } try { for (var p in e2) { t0 = a2[19]; } } catch(e1) { } Array.prototype.shift.call(a2, (yield x), b2); } }));");
/*fuzzSeed-209835301*/count=1063; tryItOut("f2 = Proxy.createFunction(h1, f0, f0);");
/*fuzzSeed-209835301*/count=1064; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.sin(( + Math.max(( + ( ! x)), ( + mathy0(Math.fround(Math.fround(Math.cosh(Math.fround(x)))), Math.fround(x)))))); }); testMathyFunction(mathy2, [1/0, 42, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, -0, 0.000000000000001, 1, -0x100000001, 0x100000001, -(2**53+2), -0x100000000, -0x0ffffffff, 0/0, 0x07fffffff, 2**53-2, Number.MIN_VALUE, -0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0x0ffffffff, -(2**53), Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, 0, -Number.MAX_VALUE, 0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-209835301*/count=1065; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((-0.03125));\n    d1 = (eval *= w);\n    (Uint16ArrayView[1]) = (\"\\uDD4F\" ? undefined : d);\n    return +((576460752303423500.0));\n    d1 = (536870913.0);\n    i0 = (/*FFI*/ff()|0);\n    d1 = (((-8796093022208.0)) * ((d1)));\n    i2 = (i2);\n    {\n      i2 = ((((i2)-(/*FFI*/ff((((((0x300f76e8))+(i0))|0)))|0))>>>(((0x38694e7e))+((((0xc26b9ef2)+(0x5c2c7b0a))>>>((0xf10f5dd9)*0xdfc6)) == (((i2))>>>((0x3e2f7e4c)-(0xe94ad4ba)-(0x598a8402))))-((274877906945.0) == (+(1.0/0.0))))));\n    }\n    switch ((((0x60a547eb) / (0x3630ff9a)) << (((0xdbeb867) > (0x561ffbec))+((-536870912.0) <= (-590295810358705700000.0))))) {\n      default:\n        d1 = (((+abs(((a = (delete x.NaN)))))) % ((-4.835703278458517e+24)));\n    }\n    d1 = (7.555786372591432e+22);\n    return +((this.zzz.zzz = function(y) { return eval }()));\n  }\n  return f; })(this, {ff: mathy1}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [1, 2**53-2, -Number.MIN_VALUE, 0x100000000, -0x080000001, -(2**53), 2**53+2, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, 0, 2**53, 1/0, 0x0ffffffff, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53-2), -(2**53+2), 42, Math.PI, Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0x100000000]); ");
/*fuzzSeed-209835301*/count=1066; tryItOut("for (var p in m2) { try { m2.get(o0.f1); } catch(e0) { } try { selectforgc(o2); } catch(e1) { } v1 = (g1 instanceof o1); }");
/*fuzzSeed-209835301*/count=1067; tryItOut(";");
/*fuzzSeed-209835301*/count=1068; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((((Math.log2(((Math.sign(( + Math.cosh(y))) | 0) | 0)) | 0) | 0) ? (Math.pow(Math.fround((Math.fround(( - Math.fround(x))) && Math.fround(Math.max((Math.fround(y) >= Math.hypot(y, x)), Math.fround(y))))), ( + ( - ( + (x ** y))))) | 0) : ( ! (((Math.acosh(Math.imul(( + x), ( + y))) | 0) ** (y | 0)) | 0))) | 0); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 2**53, 0/0, Number.MAX_VALUE, 0.000000000000001, 2**53+2, -0x100000000, 1, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -Number.MAX_VALUE, 42, -0x100000001, -0x080000001, 0x100000000, 0x080000000, 1/0, Math.PI, -0, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, 2**53-2, -Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 0x07fffffff, -(2**53), -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1069; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.max(Math.atan(0x07fffffff), (Math.atan((Math.tan(Math.max(x, (Math.fround(y) < ((( ! y) >>> 0) | 0)))) | 0)) >>> 0)), ( ~ (Math.clz32(( + (( + Math.fround(Math.max(Math.pow(x, (y ? y : x)), 0x100000001))) ? (Math.exp((x | 0)) | 0) : x))) >>> 0))); }); testMathyFunction(mathy0, [-(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -0, 0.000000000000001, 1/0, 2**53-2, 2**53, 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, -0x100000000, 42, -0x0ffffffff, -0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000001, 2**53+2, 1.7976931348623157e308, 0/0, 0, -0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, 0x080000001, -1/0, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1070; tryItOut("var pchjrw = new SharedArrayBuffer(8); var pchjrw_0 = new Int32Array(pchjrw); print(pchjrw_0[0]); pchjrw_0[0] = -24; var pchjrw_1 = new Uint8ClampedArray(pchjrw); pchjrw_1[0] = -5; var pchjrw_2 = new Float32Array(pchjrw); pchjrw_2[0] = 19; var pchjrw_3 = new Uint8Array(pchjrw); print(pchjrw_3[0]); pchjrw_3[0] = -2; var pchjrw_4 = new Float64Array(pchjrw); pchjrw_4[0] = -2; var pchjrw_5 = new Uint8Array(pchjrw); pchjrw_5[0] = 26; var pchjrw_6 = new Uint8ClampedArray(pchjrw); print(pchjrw_6[0]); print(pchjrw_2[3]);for (var v of a0) { Object.defineProperty(this, \"this.o1.b2\", { configurable: false, enumerable: false,  get: function() {  return t0.buffer; } }); }g2.v2 = a0.every(new Function, a0, p0);((Int16Array).call(new new RegExp(\"(?:[^]\\\\3*?)\", \"m\").getMinutes(), delete pchjrw_4[0].y));");
/*fuzzSeed-209835301*/count=1071; tryItOut("/*oLoop*/for (pkrsei = 0; pkrsei < 78; ++pkrsei) { print(x); } ");
/*fuzzSeed-209835301*/count=1072; tryItOut("\"use strict\"; for (var p in m2) { try { v0 = true; } catch(e0) { } try { g1.v2 = 4.2; } catch(e1) { } for (var v of o2.o2) { a0 + v2; } }");
/*fuzzSeed-209835301*/count=1073; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - (Math.atan2((Math.max(( + (( + Math.acos(x)) ? (0x0ffffffff | 0) : Math.fround((( ~ (y | 0)) | 0)))), ( ~ -0x080000001)) | 0), ((y ? (Math.fround(Math.cosh(( + Math.fround(x)))) >>> 0) : Math.imul((Math.max((x | 0), Math.fround(x)) | 0), ( ~ Math.fround(x)))) ? Math.fround(( - Math.fround((( ~ Math.fround(x)) | 0)))) : (Math.pow(x, ( + (Math.fround(x) === (x ? (y | 0) : x)))) >= (((x >>> 0) ? (x >>> 0) : (y >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy0, [42, 0x100000000, 0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -(2**53-2), -(2**53), 2**53, 0x100000001, 0x07fffffff, 1/0, -0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -0x07fffffff, -0x100000001, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -1/0, Number.MIN_VALUE, -(2**53+2), -0x100000000, 0x080000000, Number.MAX_VALUE, -0, 1, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1074; tryItOut("/*oLoop*/for (nzrrbj = 0; nzrrbj < 55; ++nzrrbj) { print( \"\" ); } ");
/*fuzzSeed-209835301*/count=1075; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=1076; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.max((( - Math.exp(Math.hypot((Number.MIN_VALUE | 0), x))) | 0), Math.fround((Math.fround(\u3056, eval = (/\\1*?/gyim.__defineSetter__(\"x\", a =>  { yield \"\\u235C\" } )), eval = (--this)) !== Math.fround(Math.min((( ~ (Math.abs(Math.PI) | 0)) | 0), (Math.pow((Math.imul(0.000000000000001, y) | 0), (x | 0)) >>> 0)))))), (( + Math.hypot(( + (Math.hypot(y, ( + y)) >>> 0)), ((Math.min(Math.fround((mathy0((x | 0), (0x100000001 | 0)) | 0)), (Math.max(x, y) | 0)) | 0) | 0))) > mathy0(Math.fround((( + (( + y) <= ( + (( + (y >>> 0)) >>> 0)))) ^ Math.min(Math.atan2((-0x0ffffffff | 0), -0x100000001), y))), x))); }); testMathyFunction(mathy1, [-0x100000001, -0x100000000, 42, 1, -0x080000000, -(2**53), 2**53+2, 0, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, -0, -0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, -1/0, -0x080000001, 1/0, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-209835301*/count=1077; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=1078; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1079; tryItOut("\"use strict\"; v1 = a0.length;");
/*fuzzSeed-209835301*/count=1080; tryItOut("mathy1 = (function(x, y) { return (mathy0(((( - Math.hypot(0/0, ( + y))) !== Math.imul(x, Math.fround(Math.min(( + (y <= ( + -(2**53-2)))), 0.000000000000001)))) >>> 0), (Math.fround((((Math.imul((Math.asin((( ~ (y >>> 0)) >>> 0)) >>> 0), (( ! y) >>> 0)) >>> 0) | 0) < (((Math.fround(( ~ Math.sin(y))) | 0) ? (Math.log2((Math.max(( + y), ( + y)) | 0)) | 0) : (Math.fround(mathy0(Math.fround((((y >>> 0) << (Math.atanh(x) >>> 0)) >>> 0)), Math.fround((Math.acos((Math.fround(mathy0(Math.fround(0x100000000), Math.fround(x))) >>> 0)) >>> 0)))) | 0)) | 0))) >>> 0)) | 0); }); testMathyFunction(mathy1, [0x080000000, 0/0, 1/0, Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 1, -0x07fffffff, -(2**53+2), -0x080000000, 2**53+2, 0x07fffffff, 0, Number.MIN_VALUE, 0x100000000, -0x100000001, -0x080000001, -Number.MAX_VALUE, 2**53-2, 42, 0x100000001, 1.7976931348623157e308, 2**53, -0, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1081; tryItOut("\"use strict\"; p2.__iterator__ = (function(j) { if (j) { try { v2 = g2.o2.g0.eval(\"x\"); } catch(e0) { } g1.a0.pop(v1, a1); } else { Array.prototype.shift.call(a1); } });");
/*fuzzSeed-209835301*/count=1082; tryItOut("m1.has(a0);print(x);let z = (delete) = eval;");
/*fuzzSeed-209835301*/count=1083; tryItOut("print((yield y ^ \"\\uF350\"));function NaN(-18, x)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+(0.0/0.0));\n    d1 = (+(-1.0/0.0));\n    return (((0x7528fb53)-((((0x401611fb)+(-0x8000000)-(!(0xffffffff))) ^ ((0xa573cf83)+(0x1129cbd3)+((((0xfb1e03fa)) >> ((-0x8000000))) < (((0x53a0d0aa)) & ((0x7de36f94)))))) > ((((-0xfffff*(0xffffffff))>>>((0xffffffff) / (0x72658788))) % (0x1296c17c)) | (x)))))|0;\n  }\n  return f;t2[11] = (delete x.x);");
/*fuzzSeed-209835301*/count=1084; tryItOut("a2.reverse(p1);");
/*fuzzSeed-209835301*/count=1085; tryItOut("\"use strict\"; M:with({c: this}){v0 = m2[\"lastIndexOf\"];(\"\\u8AE9\"); }");
/*fuzzSeed-209835301*/count=1086; tryItOut("\"use strict\"; L:for(let x = intern((((function a_indexing(pymzim, isfueq) { ; if (pymzim.length == isfueq) { ; return Math.clz32(-3); } var dbzcwv = pymzim[isfueq]; var omwqpv = a_indexing(pymzim, isfueq + 1); return (p={}, (p.z = true)()); })(/*MARR*/[x, x, x, \"\\u864A\", x, \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", \"\\u864A\", x, \"\\u864A\", x, \"\\u864A\", \"\\u864A\", \"\\u864A\", x, x, x], 0)).watch(\"0\",  /x/ ))) in (timeout(1800))) {(4277).throw(1);Array.prototype.splice.apply(o0.a2, [NaN, ]); }");
/*fuzzSeed-209835301*/count=1087; tryItOut("\"use strict\"; const \u3056 = Math.imul(-23, new (timeout(1800))()), \u3056 = x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: Function, fix: function() { throw 3; }, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function(y) { print(y); }, }; })(new RegExp(\"((\\\\D(?:(?:\\\\B))))\", \"im\")), undefined), [] = 'fafafa'.replace(/a/g, (function(x, y) { \"use strict\"; return Math.asinh((( + Math.cosh(y)) * Math.pow(Math.log1p(x), -(2**53-2)))); })), x = Object.defineProperty(NaN, \"toLocaleString\", ({get: 24})), \u3056;v0 = a0.every((function() { try { Object.defineProperty(this, \"f1\", { configurable: false, enumerable: \n /x/ ,  get: function() {  return Proxy.createFunction(h0, f2, f1); } }); } catch(e0) { } try { v0 = this.r2.test; } catch(e1) { } try { m0.has(o0.g2.f0); } catch(e2) { } for (var p in m2) { try { v0 = t1.byteLength; } catch(e0) { } try { h0.getOwnPropertyNames = String.fromCodePoint; } catch(e1) { } try { v2 = a0.length; } catch(e2) { } m1 = new Map(f0); } return p1; }), v2, f1);");
/*fuzzSeed-209835301*/count=1088; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(Math.atan2(Math.log10(( ! ( + ( ~ y)))), Math.fround((Math.log2((-Number.MIN_SAFE_INTEGER | 0)) | 0))))); }); testMathyFunction(mathy0, [-(2**53+2), 1.7976931348623157e308, 0x100000000, -0x0ffffffff, -(2**53), -0x100000001, Number.MAX_VALUE, -(2**53-2), 2**53-2, 1, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, -Number.MIN_VALUE, 0x080000001, 42, 2**53+2, Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0, -0, 0.000000000000001, 2**53, -Number.MAX_VALUE, 1/0, -0x080000000, 0x07fffffff, 0/0]); ");
/*fuzzSeed-209835301*/count=1089; tryItOut("\"use strict\"; var cqdlgu = new SharedArrayBuffer(8); var cqdlgu_0 = new Int16Array(cqdlgu); print(cqdlgu_0[0]); cqdlgu_0[0] = 5; var cqdlgu_1 = new Int16Array(cqdlgu); cqdlgu_1[0] = 26; var cqdlgu_2 = new Uint16Array(cqdlgu); cqdlgu_2[0] = 6; var cqdlgu_3 = new Uint32Array(cqdlgu); cqdlgu_3[0] = -17; var cqdlgu_4 = new Int8Array(cqdlgu); print(cqdlgu_4[0]); var cqdlgu_5 = new Uint8ClampedArray(cqdlgu); cqdlgu_5[0] = -20; var cqdlgu_6 = new Uint16Array(cqdlgu); /* no regression tests found */");
/*fuzzSeed-209835301*/count=1090; tryItOut("mathy5 = (function(x, y) { return (mathy4(( + ( - ( - (( ~ x) | 0)))), Math.fround(mathy3((Math.pow(Math.clz32(Math.fround((Math.fround(Math.fround(Math.ceil(Math.fround(y)))) && Math.fround(( ~ y))))), Math.fround((( - (0x080000001 | 0)) / (y , 1/0)))) >>> 0), Math.fround(Math.sign(Math.fround(mathy0((((mathy1(y, (( + Math.fround(0)) >>> 0)) | 0) - (y >>> 0)) | 0), (y | 0)))))))) >>> 0); }); testMathyFunction(mathy5, ['', (function(){return 0;}), objectEmulatingUndefined(), 0.1, '/0/', ({valueOf:function(){return '0';}}), '0', -0, null, (new Number(-0)), undefined, (new String('')), false, ({valueOf:function(){return 0;}}), NaN, ({toString:function(){return '0';}}), (new Boolean(false)), /0/, 1, [], 0, true, [0], '\\0', (new Boolean(true)), (new Number(0))]); ");
/*fuzzSeed-209835301*/count=1091; tryItOut("(new RegExp(\"[^]|[\\\\v-\\\\xd7\\\\\\ua9b6-\\ue108\\\\D](?!(\\\\2)){4194304,4194305}\", \"ym\"));function x(\u3056) { \"use strict\"; ( \"\" ); } d;");
/*fuzzSeed-209835301*/count=1092; tryItOut("/*vLoop*/for (var fcrcux = 0; fcrcux < 40; ++fcrcux) { const z = fcrcux; for (var p in t2) { try { t0[0]; } catch(e0) { } t1[3] = a1; } } ");
/*fuzzSeed-209835301*/count=1093; tryItOut("\"use strict\"; print(x);g0.v1 = Object.prototype.isPrototypeOf.call(p2, g2.m1);");
/*fuzzSeed-209835301*/count=1094; tryItOut("a0 = [];");
/*fuzzSeed-209835301*/count=1095; tryItOut("print(i1);");
/*fuzzSeed-209835301*/count=1096; tryItOut("var xkvhfb = new SharedArrayBuffer(8); var xkvhfb_0 = new Uint8ClampedArray(xkvhfb); xkvhfb_0[0] = -18; var xkvhfb_1 = new Int16Array(xkvhfb); xkvhfb_1[0] = 26; var xkvhfb_2 = new Float64Array(xkvhfb); xkvhfb_2[0] = -3; var xkvhfb_3 = new Float64Array(xkvhfb); xkvhfb_3[0] = 3; var xkvhfb_4 = new Uint32Array(xkvhfb); var xkvhfb_5 = new Int16Array(xkvhfb); xkvhfb_5[0] = 0.82; var xkvhfb_6 = new Float32Array(xkvhfb); xkvhfb_6[0] = 19; var xkvhfb_7 = new Int16Array(xkvhfb); print(xkvhfb_7[0]); xkvhfb_7[0] = -2; var xkvhfb_8 = new Uint8ClampedArray(xkvhfb); var xkvhfb_9 = new Uint8Array(xkvhfb); print(xkvhfb_9[0]); e2.delete(o0.g0.t2);(p={}, (p.z = 0.689)());print(xkvhfb_9[0]);h0.__proto__ = i0;v2 = a1.length;g1.h0.getOwnPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+(0.0/0.0));\n    d0 = (d0);\n    i1 = (true);\n    (Float32ArrayView[((i1)*-0x10676) >> 2]) = ((-2.3611832414348226e+21));\n    i1 = (i1);\n    {\n      i1 = (1);\n    }\n    d0 = (d0);\n    return (((i1)))|0;\n  }\n  return f; });print(xkvhfb_5);v1 = g0.runOffThreadScript();this.e2 + p1;");
/*fuzzSeed-209835301*/count=1097; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-209835301*/count=1098; tryItOut("for (var p in e1) { try { Object.prototype.unwatch.call(s0, \"__parent__\"); } catch(e0) { } try { v2 = t1.length; } catch(e1) { } try { o0.e0 = new Set; } catch(e2) { } let v1 = g1.runOffThreadScript(); }");
/*fuzzSeed-209835301*/count=1099; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(Math.fround(mathy1(Math.fround((( + ((Math.fround(Math.abs(Math.fround(2**53+2))) * (( ~ Number.MAX_VALUE) , x)) >>> 0)) >>> 0)), Math.fround(Math.acosh((Number.MIN_SAFE_INTEGER - y))))), ((Math.fround((( - Math.fround(mathy1(Math.fround(new String(\"-14\")), y))) !== y)) % ((Math.acos(Math.abs(( + ( ~ ( + (Math.tan((y >>> 0)) >>> 0)))))) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -0x080000000, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 0x080000001, -0x0ffffffff, Number.MIN_VALUE, -1/0, -0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -0x080000001, 1.7976931348623157e308, 1, -(2**53+2), -0x100000000, -0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0.000000000000001, 2**53+2, 0x0ffffffff, -(2**53), 2**53-2, 0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001]); ");
/*fuzzSeed-209835301*/count=1100; tryItOut("/*iii*/window = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: undefined, enumerate: function() { throw 3; }, keys: undefined, }; })(new RegExp(\"\\\\b((?=[^\\\\u759c\\udd3b\\\\D]|\\\\B.|(?=[\\\\\\u9002\\\\B-\\u00c0]){16777217,}))\", \"gyi\")), x ^ x);/*hhh*/function xrmiou({}, a){/* no regression tests found */}");
/*fuzzSeed-209835301*/count=1101; tryItOut("i1.next();");
/*fuzzSeed-209835301*/count=1102; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1103; tryItOut("mathy4 = (function(x, y) { return (Math.min(Math.fround((Math.imul(((( ~ ((Math.min(y, ( + (((y - x) >>> 0) ? x : Math.PI))) >>> 0) >>> 0)) >>> 0) | 0), (Math.tanh((( + x) >>> 0)) | 0)) | 0)), ( ! mathy2(Math.fround((Math.clz32(x) | 0)), x))) >>> 0); }); ");
/*fuzzSeed-209835301*/count=1104; tryItOut("\"use strict\"; g2.o1.e2 + '';\n[z1];\n");
/*fuzzSeed-209835301*/count=1105; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1106; tryItOut("mathy4 = (function(x, y) { return ( + Math.fround(( - ((mathy1(( + mathy1(Math.fround(Math.min(-Number.MAX_VALUE, x)), ( + (( - (0x100000000 | 0)) | 0)))), ( + (( + (((-(2**53) >>> 0) != y) | 0)) ? ( + 1/0) : (x | 0)))) >>> 0) , Math.exp(( ! 1)))))); }); testMathyFunction(mathy4, [0, 1, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 2**53-2, 1/0, 42, -1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 0x0ffffffff, -0x080000000, -0, 0x07fffffff, 0x100000001, -0x100000000, 1.7976931348623157e308, 0x100000000, 0/0, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=1107; tryItOut("/*ADP-3*/Object.defineProperty(a0, 3, { configurable: false, enumerable: true, writable: ((void shapeOf(x--))), value: v0 });\nObject.prototype.unwatch.call(o0, 12);\n");
/*fuzzSeed-209835301*/count=1108; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1109; tryItOut("m0.get(-8);var a = a <<= c;");
/*fuzzSeed-209835301*/count=1110; tryItOut("var this.x, e = \"\\uFDD6\", vsfeib, x = x, x = x;b0 = new SharedArrayBuffer(72);");
/*fuzzSeed-209835301*/count=1111; tryItOut("\"use strict\"; o2.v1 = t1.length;");
/*fuzzSeed-209835301*/count=1112; tryItOut("\"use strict\"; v1 = evaluate(\"g1.g2.toSource = (function mcc_() { var szwmhy = 0; return function() { ++szwmhy; f2(/*ICCD*/szwmhy % 9 == 7);};})();\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 2 != 0), catchTermination: (x % 5 != 4) }));");
/*fuzzSeed-209835301*/count=1113; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = ((d1) < (34359738368.0));\n    d1 = (((d1)) - (((/*FFI*/ff(((~~((0xf9935fd7) ? (-67108863.0) : (2.4178516392292583e+24)))), ((+((d0)))))|0) ? (d1) : (d0))));\n    return ((((((Uint8ArrayView[((0x51fcad07)) >> 0]))) & ((0x0) % (0xedeff3af))) / (~((0x6fc2e781)+((-0x84dbb*(!(0xb6a1cd78))))))))|0;\n  }\n  return f; })(this, {ff: String.prototype.valueOf}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53), 0.000000000000001, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, 0x100000001, 1, Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x100000000, -1/0, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 2**53, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, 42, -(2**53+2), 0x080000001, 0, -0]); ");
/*fuzzSeed-209835301*/count=1114; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, -1/0, -(2**53), Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), 0x100000001, -(2**53-2), 0.000000000000001, 0x0ffffffff, 2**53, 2**53+2, -0, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, -0x100000000, 0, 0x07fffffff, 1.7976931348623157e308, 0/0, -0x080000000, -Number.MIN_VALUE, 42, -0x07fffffff, Math.PI, -0x100000001, 0x080000000]); ");
/*fuzzSeed-209835301*/count=1115; tryItOut("\"use strict\"; new (q => q)((\"\u03a0\")());");
/*fuzzSeed-209835301*/count=1116; tryItOut("h1.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = a5 * a10; var r1 = 9 & a1; var r2 = 5 % a5; var r3 = 0 % 3; var r4 = a2 % x; var r5 = a10 % a2; x = a8 * a8; var r6 = a7 / a3; var r7 = a7 + a12; var r8 = 0 % a1; var r9 = a0 % a3; var r10 = 5 ^ 4; print(r1); var r11 = r10 / a9; a5 = 2 ^ 5; var r12 = a7 % r0; var r13 = 5 % r0; print(r6); var r14 = 5 + 0; r0 = 6 ^ a12; var r15 = a1 % 9; a3 = a1 / a0; var r16 = 1 * a2; var r17 = a2 / r8; r5 = a7 * a7; var r18 = a5 * 4; var r19 = r8 - 2; print(r6); var r20 = 0 - a9; var r21 = r4 - a0; var r22 = r3 & 0; var r23 = a9 - r16; a1 = r1 & 4; r15 = 8 ^ 6; var r24 = 4 & 8; var r25 = r11 | r13; var r26 = 6 & a6; var r27 = r11 + a4; r3 = a5 % a0; var r28 = r18 % r25; var r29 = r16 / 7; print(a2); var r30 = 2 ^ r11; var r31 = 6 ^ a11; var r32 = 9 | r13; var r33 = 4 / r9; var r34 = r13 | a7; var r35 = 9 & 7; var r36 = r32 & r20; var r37 = a6 + 9; var r38 = r20 / r29; r10 = r28 % 0; var r39 = a8 ^ r21; var r40 = r30 / a11; var r41 = a0 - r24; var r42 = a12 ^ a11; var r43 = r33 * r33; var r44 = r3 & 3; var r45 = 5 / r13; return a8; });/*infloop*/do {/*oLoop*/for (let hqqkye = 0, 7; (\"\\uBBFF\") && hqqkye < 23; ++hqqkye) { null; }  } while((TypeError(\"\\u2D77\",  '' )));");
/*fuzzSeed-209835301*/count=1117; tryItOut("M:switch((b) < [[]].watch(\"tan\", Math.min(new RegExp(\"(?=(?!(?:[^])+?)\\\\B|$*+?$?[^][^]\\\\2^*)\", \"yim\"), this))) { default: for (var v of i1) { try { e2.delete(h2); } catch(e0) { } try { this.e1.has(a2); } catch(e1) { } v1 = new Number(b1); }break; case 3: let (x) { i2 = e0.values; }break; s0 += s0;break; break; case 5: case 5: break; case 0: print(x);case 1: break;  }");
/*fuzzSeed-209835301*/count=1118; tryItOut("/*oLoop*/for (let chraee = 0; chraee < 61; ++chraee) { this.g0.i2.send(this.m2); } function x(NaN, x) { yield 3 } g0.offThreadCompileScript(\"h1.getOwnPropertyDescriptor = f2;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: ({x: -24(true.unwatch(\"-9\"), null), x: (yield (eval(\"/* no regression tests found */\", -25))) }), noScriptRval: true, sourceIsLazy: false, catchTermination: true, element: o1, sourceMapURL: o0.s2 }));");
/*fuzzSeed-209835301*/count=1119; tryItOut("\"use strict\"; print(x);/*MXX2*/this.g1.Proxy.length = a0;");
/*fuzzSeed-209835301*/count=1120; tryItOut("b1 = t2.buffer;");
/*fuzzSeed-209835301*/count=1121; tryItOut("mathy5 = (function(x, y) { return ( - (Math.fround(Math.max(((Math.asinh(((((x || x) * x) >>> ( + 2**53-2)) >>> 0)) >>> 0) | 0), (( + Math.trunc((( + -0x0ffffffff) >>> 0))) >>> 0))) >>> 0)); }); ");
/*fuzzSeed-209835301*/count=1122; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return (((mathy0(mathy1(( ! x), ( + Math.atan2(x, (y >= x)))), Math.log(mathy0(( ! y), ((Math.hypot(y, (-0x100000001 | 0)) | 0) >>> 0)))) | 0) / (Math.sign(Math.atanh((Math.max((Math.clz32(Math.hypot(x, Math.exp((x | 0)))) >>> 0), ((Math.hypot(( + 0x080000001), ( - 2**53-2)) | 0) >>> 0)) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-209835301*/count=1123; tryItOut("\"use strict\"; { void 0; selectforgc(this); } /* no regression tests found */");
/*fuzzSeed-209835301*/count=1124; tryItOut("((4277));");
/*fuzzSeed-209835301*/count=1125; tryItOut("b2 + m2;");
/*fuzzSeed-209835301*/count=1126; tryItOut("mathy5 = (function(x, y) { return Math.atan2(( ~ ((-Number.MIN_SAFE_INTEGER % x) - (( + mathy0(( + 2**53+2), ( + (x - (Math.fround(( ! x)) | 0))))) << (( ! (y >>> 0)) >>> 0)))), ( ~ ((Math.tanh(Math.imul(Math.pow((x | 0), (x >>> 0)), y)) !== Math.fround((Math.atan2(Number.MAX_VALUE, 0.000000000000001) << x))) | 0))); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x100000001, -0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, -0, 0x07fffffff, 0x0ffffffff, 0/0, 1/0, Math.PI, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, -(2**53-2), 2**53-2, -0x07fffffff, 2**53, 0, 0.000000000000001, -1/0, -(2**53+2), 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 1, Number.MAX_SAFE_INTEGER, 42, 2**53+2, 0x080000001]); ");
/*fuzzSeed-209835301*/count=1127; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log((( - ((x === Math.fround(((((((1.7976931348623157e308 | 0) !== x) | 0) >>> 0) % ((Math.trunc(Math.fround(x)) >>> 0) >>> 0)) >>> 0))) | 0)) >> ( + Math.sign(Math.fround((y || (y >>> 0))))))); }); testMathyFunction(mathy2, [NaN, true, objectEmulatingUndefined(), 0, (new Number(0)), /0/, undefined, [0], '\\0', (new Number(-0)), -0, 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), false, 1, (new Boolean(true)), [], '0', (new String('')), ({valueOf:function(){return '0';}}), null, (new Boolean(false)), '/0/', (function(){return 0;}), '']); ");
/*fuzzSeed-209835301*/count=1128; tryItOut("testMathyFunction(mathy0, [Math.PI, 0x100000001, 1, -(2**53), -0x0ffffffff, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, 0x080000000, 0x100000000, 2**53+2, 2**53, 0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, -0x080000000, -0, -0x07fffffff, -1/0, 0/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0x100000000, 42, 0, 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=1129; tryItOut("mathy4 = (function(x, y) { return Math.imul(( + ((( - Math.fround(Math.min(y, Math.fround(Math.fround(Math.atan2(Math.fround(x), Math.fround((( ~ ( + x)) | 0)))))))) >>> 0) ? Math.fround((Math.fround(Math.atan2(x, y)) != (( + ( ! x)) ^ Math.fround(x)))) : ( + Math.max(( + ( ! x)), ( + (2**53+2 ** (( + Number.MAX_VALUE) >>> 0))))))), ( + (( + Math.min(( + Math.tan(( + x))), ( + (-1/0 ** ( + y))))) <= (Math.fround((Math.fround(Math.trunc((Math.hypot(x, x) >>> 0))) , Math.fround(Math.atan(Math.imul(Math.hypot(x, ( - -Number.MAX_SAFE_INTEGER)), (x >>> 0)))))) >>> 0)))); }); testMathyFunction(mathy4, [-0, Number.MAX_VALUE, 2**53-2, -(2**53+2), -(2**53-2), 0x07fffffff, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0x0ffffffff, 0x100000000, 2**53, 0x080000000, 0/0, 1, -0x080000001, 42, -0x080000000, -0x100000001, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1130; tryItOut("x >>= ((new (function (NaN, eval, NaN, a, eval, x, x, b =  /x/ , d, \u3056, window, eval, a = /r{4,}/im, x, window = \"\\uA4C7\", NaN, eval, x, x, y, x, z, x = y, x =  /x/ , x, x = new RegExp(\"(?=(((?:\\\\x16)|(?:.)*\\\\u00Aa)))\", \"\"), x, this.x, window, x, e, x, 6, x, e, z, NaN = new RegExp(\"(?=[^]*)?\", \"ym\"), a, b, e, y = this, NaN, a, x = undefined, x, y, a, b, b, window, x = true, x, x, x, eval, x, \u3056, e, c, x, window, e, x)6).call()).unwatch(18));");
/*fuzzSeed-209835301*/count=1131; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.imul(((Math.acos(x) ? mathy1(((x <= y) | 0), x) : Math.min(y, Math.atan2(x, Math.fround(y)))) >>> 0), (Math.atan2(Math.max(x, y), Math.cbrt(Math.sinh(x))) >>> 0)) ? (Math.fround(Math.atan2(Math.fround(Math.min(y, (Math.fround(y) != ( + y)))), Math.fround(y))) + Math.fround(Math.trunc(0x07fffffff))) : (Math.max(Math.asin(x), y) >>> ((( + (( + Math.log2(( + (( - 2**53-2) >= mathy1(y, x))))) | 0)) | 0) | 0))) >>> 0); }); testMathyFunction(mathy3, [0x100000001, -0x07fffffff, -0x100000000, -0x0ffffffff, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, 2**53-2, 42, 0, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, 2**53+2, -0, 1/0, 2**53, 0x080000001, 0x07fffffff, -0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-209835301*/count=1132; tryItOut("v2 = (i0 instanceof o1.f1);");
/*fuzzSeed-209835301*/count=1133; tryItOut("t2[15] = {};");
/*fuzzSeed-209835301*/count=1134; tryItOut("o0 = {};");
/*fuzzSeed-209835301*/count=1135; tryItOut("Object.preventExtensions(g0.h1);function this.x(( /x/g )(\"\\u142D\"), x, x, window, x, eval = new RegExp(\".?\", \"ym\"), eval, d, x =  /x/g , eval, x, x = new RegExp(\"\\\\s{3,7}(?!\\\\cL+)*\", \"yi\"), delete, d, x =  '' , get =  /x/ , x, x, x, x, e, window = length, z, y = -8, e, e, w, x, x, y, x, window, window, \u3056 = undefined, c, x, x, x, e, z = null, NaN, y, x =  '' , w, x =  /x/g , \"26\", z, this.x, x, b, x = this, x, x, x = -4, NaN, x, x, x, x, x, x, x, e, x = null, eval, \u3056, x, w, eval = x, x, window = \"\\u0514\", x, x, x, x)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float64ArrayView[(((-((0x7957126c))) >> ((0x43fc606f) % (0xf6ea385e))) % (((1)) & ((1)))) >> 3]) = ((d1));\n    i0 = (0xfd1734a8);\n    return +((d1));\n  }\n  return f;function shapeyConstructor(alyndp){\"use asm\"; return this; }");
/*fuzzSeed-209835301*/count=1136; tryItOut("s2.__proto__ = g0.g2.m2;");
/*fuzzSeed-209835301*/count=1137; tryItOut("if(13) { if (x) {m2.delete(g2);g1.offThreadCompileScript(\"function f1(o0)  { \\\"use strict\\\"; yield window } \", ({ global: o0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 == 0), sourceIsLazy: true, catchTermination: (x % 4 != 2), element: o2.o0, elementAttributeName: s0, sourceMapURL: s1 })); }} else /*oLoop*/for (let aezrzw = 0; ( \"\" ) && aezrzw < 111; this, ++aezrzw) { ( '' ); } /*hhh*/function huiamj(x, ...x){for (var v of m0) { try { o1.v2 = g0.g2.runOffThreadScript(); } catch(e0) { } try { this.o2.v0 = g0.g0.eval(\"/* no regression tests found */\"); } catch(e1) { } o1.f1 + ''; }}huiamj([,,], this.w);");
/*fuzzSeed-209835301*/count=1138; tryItOut("v0 = (s1 instanceof p2);");
/*fuzzSeed-209835301*/count=1139; tryItOut("\"use strict\"; /*infloop*/for(var a = /*RXUE*/this.exec(\"\\u5bb4\"); (e%=null ?  /x/  : [] ** ({/*toXFun*/valueOf: offThreadCompileScript })); /(?=\\xEF\\2{1,3}+)/g.prototype) v2 = a0.length;");
/*fuzzSeed-209835301*/count=1140; tryItOut("/*oLoop*/for (lgsvjg = 0; lgsvjg < 4; ++lgsvjg) { this.v0 = Object.prototype.isPrototypeOf.call(v2, i1); } ");
/*fuzzSeed-209835301*/count=1141; tryItOut("a0 = arguments;");
/*fuzzSeed-209835301*/count=1142; tryItOut("mathy5 = (function(x, y) { return Math.asinh(mathy4(Math.acos(Math.fround(mathy3(y, Math.fround(y)))), Math.hypot(Math.atanh(mathy2(Math.asin(-0x080000000), y)), Math.cosh((((x | 0) ^ y) | 0))))); }); testMathyFunction(mathy5, [-0, 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 0x100000000, -(2**53), 42, Number.MAX_VALUE, 2**53-2, 2**53+2, -0x0ffffffff, 0.000000000000001, Math.PI, -0x080000000, -0x100000001, -Number.MIN_VALUE, 1/0, 0/0, 0x080000000, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE, -0x100000000, 0x07fffffff, 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=1143; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.hypot(Math.hypot((mathy2((( ! (x | 0)) | 0), ( + (mathy0((Math.pow((((x | 0) >= ( ~ y)) | 0), ( + y)) >>> 0), ((-1/0 >>> 0) < (y >>> 0))) | 0))) | 0), ((Math.atanh((x * (( + (( + -1/0) | -0)) ? Math.fround(-Number.MAX_SAFE_INTEGER) : Math.fround(x)))) ? Math.atan2(y, x) : Math.fround(( + ( + Math.fround((Math.hypot(y, ( + y)) & (Math.fround(( ~ y)) >>> 0))))))) | 0)), ( - (x ? b &= d : x+=window | 0))); }); testMathyFunction(mathy3, [-0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -(2**53-2), 1.7976931348623157e308, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 1, 2**53-2, -0x080000001, 0.000000000000001, 0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000000, -0, 0x100000001, 2**53+2, Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, -0x100000000, 0x080000000, -0x100000001, 0, Number.MAX_SAFE_INTEGER, 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, 42, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=1144; tryItOut("x = null, x = Math.pow(-14, 3), x = window ===  \"\" , c, x = [1], x, urgvme, \u3056, x, x;print(x);");
/*fuzzSeed-209835301*/count=1145; tryItOut("\"use strict\"; a1.toString = (function(j) { if (j) { try { v1 = Object.prototype.isPrototypeOf.call(s1, p2); } catch(e0) { } Object.prototype.watch.call(i2, \"wrappedJSObject\", (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (!((((((d1) + (281474976710656.0)))-((0xa9bd6b2d))) | (-0x7028e*((~((0x137a744e)+(0xfa6078bc)+(0x2e4916c2))) > (((0xfaa44d44)) | ((0xde0b1f18)))))) != (abs((~((i0))))|0)));\n    return +((((+(-1.0/0.0))) * ((1.0))));\n    {\n      i0 = ((((Int8ArrayView[(null) >> 0])) | ((i0)+(0x49e3fd46))));\n    }\nprint(uneval(b2));    d1 = (+(-1.0/0.0));\n;    (x) = ((i0));\n    i0 = ((0xbd6e9032) ? (i0) : ((0x0) == (((0xe63dcade))>>>((Uint8ArrayView[2])))));\n    return +((d1));\n    i0 = (0x1c71b714);\n    (Uint16ArrayView[2]) = ((Int32ArrayView[(((timeout(1800)).x) = (4277)) >> 2]));\n    i0 = (0x6e71163b);\n    {\n      switch ((((0x5e249ef9)-(0x1098766e)-(0xd6c3ca3d)) << ((1)))) {\n        default:\n          i0 = (0xe72b1935);\n      }\n    }\n    d1 = (-590295810358705700000.0);\n    i0 = (-0x8000000);\n    i0 = ((~((0x49c2d562))));\n    {\n      i0 = (0xfbd14212);\n    }\n    (Int32ArrayView[0]) = ((x) / (0x2d829572));\n    d1 = (d1);\n    d1 = (Infinity);\n    return +((d1));\n  }\n  return f; })); } else { try { Array.prototype.pop.apply(a2, []); } catch(e0) { } v2 = a0.length; } });");
/*fuzzSeed-209835301*/count=1146; tryItOut("/*MXX1*/o1.o1 = g0.Object.getPrototypeOf;");
/*fuzzSeed-209835301*/count=1147; tryItOut("m2.set(i0, i0);");
/*fuzzSeed-209835301*/count=1148; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((0xe406a568) < (((Uint8ArrayView[(((((0x695fe802)+(0x7841ecb2)) ^ ((0x5c523ae6)*-0x96b78)))) >> 0]))>>>(((+atan2(((9.44473296573929e+21)), ((15.0)))) != (-0.015625))+(0x60515dff)+((0x9f8f024f) <= (0xffffffff)))));\n    return (((((/*FFI*/ff(((abs((((!(0xac57e87c))) >> ((0x5290b751) / (0x598ec295))))|0)))|0)+(i1)) >> ((((i1)) | ((i1)-(0xffffffff))))) / (((-0x8000000)-(!(i1))) >> (-0xb3a3b*((((i1))>>>(-(0x3a55db1d))) != (0x65a925a9))))))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var wsyqhj = x; var jsrmkt = Date.prototype.setUTCMonth; return jsrmkt;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000001, -(2**53-2), 0x080000000, 0x080000001, -1/0, Number.MIN_VALUE, 0, 2**53+2, -0x080000000, -Number.MAX_VALUE, 0.000000000000001, 2**53, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -0x100000001, 42, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, 0x07fffffff, 1, -0, 0/0, -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=1149; tryItOut("testMathyFunction(mathy0, [1/0, Math.PI, -0x100000000, 0/0, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, 0x080000000, -(2**53+2), -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0x100000000, Number.MAX_VALUE, -1/0, 0x080000001, 2**53-2, -0x07fffffff, 42, 0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 0, -0, 1]); ");
/*fuzzSeed-209835301*/count=1150; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2(Math.trunc(( - (x <= (x | 0)))), Math.cosh(((y ? (( ! x) | 0) : x) | 0))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0x080000001, -Number.MAX_VALUE, Math.PI, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, 42, -0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, 1.7976931348623157e308, -(2**53), 2**53+2, 0x100000001, -0x100000001, -(2**53+2), Number.MAX_VALUE, 1/0, 0.000000000000001, -1/0, 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0x100000000, -0x080000000, -(2**53-2), 2**53-2, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-209835301*/count=1151; tryItOut("o0.g1.v1 = undefined;");
/*fuzzSeed-209835301*/count=1152; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround(( ~ Math.fround(( ! Math.fround(Math.min(((((y !== y) >>> 0) - (Math.fround(( + Math.fround(x))) >>> 0)) >>> 0), Math.fround(Math.max(Math.fround(y), Math.max(y, ( + y)))))))))) >= Math.fround(( + (Math.trunc((Math.fround(Math.atan2(Math.fround(Math.hypot(y, y)), y)) | 0)) | 0))))); }); testMathyFunction(mathy4, [2**53-2, -(2**53-2), -0x100000000, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, 1, 0x080000000, Math.PI, 0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, -(2**53), 0, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, -(2**53+2), -0x07fffffff, 42, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x080000001, -0, -1/0, -0x080000001, 0/0]); ");
/*fuzzSeed-209835301*/count=1153; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-209835301*/count=1154; tryItOut("v0 = Object.prototype.isPrototypeOf.call(b1, m2);");
/*fuzzSeed-209835301*/count=1155; tryItOut("mathy0 = (function(x, y) { return Math.round(Math.expm1(Math.tanh((Math.pow((y >>> 0), Math.fround(Math.sign(y))) >>> 0)))); }); testMathyFunction(mathy0, [0x080000000, 0/0, -0x100000001, -(2**53-2), -(2**53+2), 0x080000001, Number.MAX_VALUE, -0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, -(2**53), 2**53-2, 2**53+2, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, 1/0, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 0x07fffffff, -0x100000000, -0x0ffffffff, 42]); ");
/*fuzzSeed-209835301*/count=1156; tryItOut("v0 = a2.reduce, reduceRight((function() { try { e0.add(o1); } catch(e0) { } a1.push(); return e1; }), h2);\n/*vLoop*/for (var sukpds = 0; sukpds < 15; ++sukpds) { let b = sukpds; s1 += 'x'; } \n");
/*fuzzSeed-209835301*/count=1157; tryItOut("Array.prototype.shift.call(a2);");
/*fuzzSeed-209835301*/count=1158; tryItOut("a1.shift(t0, m1);");
/*fuzzSeed-209835301*/count=1159; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-209835301*/count=1160; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\S?[^]*\", \"gy\"); var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=1161; tryItOut("let (  = (void options('strict')), window = [], xanyuz, btmrgc, hwxqas, c = (yield false).eval(\"/* no regression tests found */\"), NaN = ((function sum_indexing(nzgldf, rtopep) { ; return nzgldf.length == rtopep ? 0 : nzgldf[rtopep] + sum_indexing(nzgldf, rtopep + 1); })(/*MARR*/[0x100000001, 0x100000001, 0x100000001, [(void 0)], [(void 0)], this, this, [(void 0)], 0x100000001, this, this, this, this, this, this, this, this, this, this, this, this, this, ({}), this, ({}), ({}), 0x100000001, ({}), this, [(void 0)], [(void 0)], [(void 0)], [(void 0)], ({}), ({}), 0x100000001, [(void 0)], 0x100000001, this, [(void 0)], [(void 0)], ({}), 0x100000001, this, this, this, ({}), this, ({}), ({}), ({}), this, this, 0x100000001, ({}), this, 0x100000001, this, 0x100000001, [(void 0)], this, ({}), [(void 0)], this, ({}), 0x100000001, ({}), this, ({}), [(void 0)], 0x100000001, 0x100000001, this, this, [(void 0)]], 0)), ujlgql, jqwjtq) { L:do {g1.a2 = Array.prototype.filter.apply(a1, [(function() { try { Array.prototype.pop.apply(a2, [s2, /((?:\\2[^]*?){4,})/y]); } catch(e0) { } /*RXUB*/var r = r2; var s = \"\"; print(s.match(r)); print(r.lastIndex);  return s0; }), (p={}, (p.z = name >>>= x)())]);Array.prototype.unshift.call(this.o2.a1, v0, e1, e0, (makeFinalizeObserver('nursery')), a2); } while((Math.atan2(1, (allocationMarker()))) && 0); }");
/*fuzzSeed-209835301*/count=1162; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=1163; tryItOut("with(x){b1.__proto__ = t2; }");
/*fuzzSeed-209835301*/count=1164; tryItOut("M:for(let w in (makeFinalizeObserver('nursery'))()) {/*infloop*/L:for(var z; {} = this; (Function).call(x, true, -4503599627370495)) {/*infloop*/ for (x of ({} = (new Function)())) {/*hhh*/function hduvzi(\u3056, ...w){(\"\\u625E\");}/*iii*/return window; } }/* no regression tests found */ }");
/*fuzzSeed-209835301*/count=1165; tryItOut("e0.add(v1);");
/*fuzzSeed-209835301*/count=1166; tryItOut("\"use strict\"; Array.prototype.splice.apply(this.a0, [4, 2, g2]);");
/*fuzzSeed-209835301*/count=1167; tryItOut("o2.v0 = g2.runOffThreadScript();function window(z, w, c = function(id) { return id }, x = false, x = /(^|(\\b)^\\S.|(?!.\\cU\\d[^]))(\\2){65537,}{4,}/g, x, c, \u3056, c, y = this, x, x = \"\\uFA98\", x, x,  '' , c, x, w, x, x =  /x/ , y\u000c) { \"use strict\"; yield (4277) } v0 = i0[\"1\"];");
/*fuzzSeed-209835301*/count=1168; tryItOut("\"use strict\"; o1.a0.sort(Array.prototype.filter.bind(p1));");
/*fuzzSeed-209835301*/count=1169; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround(( + ( ! ( + (Math.fround(Math.tanh(Math.fround((Math.log(0x100000000) | 0)))) ? ( ! y) : (( + ( ~ ( + Math.fround(( ~ Math.fround((( ! y) | 0))))))) >>> 0)))))) * Math.trunc(( + Math.abs(( + -1/0))))); }); testMathyFunction(mathy0, [NaN, (new Number(-0)), undefined, 0.1, 1, ({valueOf:function(){return 0;}}), (new Boolean(true)), false, (new Boolean(false)), -0, /0/, (new Number(0)), objectEmulatingUndefined(), [], true, '0', '/0/', [0], null, 0, ({toString:function(){return '0';}}), '', (new String('')), '\\0', (function(){return 0;}), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-209835301*/count=1170; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    switch ((((0x699b200c)-((0x6185fbc5))) << ((i2)+(!(0x76908a0b))))) {\n      case 0:\n        return +((+(1.0/0.0)));\n        break;\n    }\n    {\n      (Float64ArrayView[0]) = ((Infinity));\n    }\n    {\n      switch ((((/*FFI*/ff(((d0)), ((-1024.0)), ((70368744177665.0)), ((-0.0009765625)), ((2251799813685249.0)), ((1.9342813113834067e+25)), ((1.888946593147858e+22)), ((-65.0)), ((1.015625)), ((36893488147419103000.0)), ((70368744177663.0)))|0)) | ((0xffffffff)+(-0x4487d91)-(0x4e1b8719)))) {\n        case -1:\n          d1 = (((new (neuter)( /* Comment */\u3056 = Proxy.createFunction(({/*TOODEEP*/})(window), Object.isExtensible)))) * ((Float64ArrayView[1])));\n          break;\n        default:\n          {\n            d1 = ((0xffffffff) ? (0.0078125) : (+(0.0/0.0)));\n          }\n      }\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x080000000, -(2**53), -0x100000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -0x07fffffff, -0x080000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 42, 1, -(2**53-2), 0.000000000000001, -0, Math.PI, 2**53-2, -1/0, 1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, 0x100000000, 0x080000000, 0x0ffffffff, Number.MIN_VALUE, -0x100000000, 2**53]); ");
/*fuzzSeed-209835301*/count=1171; tryItOut("f2(o1);");
/*fuzzSeed-209835301*/count=1172; tryItOut("v2 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-209835301*/count=1173; tryItOut("Array.prototype.forEach.apply(a1, [(function() { h1.__proto__ = a0; return v0; })]);");
/*fuzzSeed-209835301*/count=1174; tryItOut("let x, amooqj, [, ] = let (y) x, x =  /x/g , NaN = let (c) d in (function(x, y) { \"use strict\"; return x; })(), qkdlpm, x = new (x ? x : (4277))(/*FARR*/[]\u0009.filter((let (e=eval) e), delete), x), x = encodeURIComponent;/*hhh*/function hjyhfk(y, z, ...x){v0 = evaluate(\"mathy3 = (function(x, y) { return (((( + ((Math.log((( + Math.min(( + Math.fround((Math.fround(( + Math.pow((-Number.MAX_VALUE >>> 0), ( + (x ? (-0 | 0) : -0x100000001))))) / Math.fround(( + Math.min(( + x), (y | 0))))))), ( + -(2**53-2)))) >>> 0)) >>> 0) || Math.imul(-(2**53-2), (Math.hypot(2**53-2, (Math.hypot(Math.fround(y), y) | 0)) || (y >>> 0))))) | 0) <= (Math.fround(Math.cosh((Math.min(Math.asinh(x), ((Math.fround(( ! ( + x))) > Math.PI) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, 0, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, 42, -1/0, -0x100000000, 0x080000001, -Number.MAX_VALUE, Math.PI, 0x100000001, 0x07fffffff, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 1, -0x080000001, -0x07fffffff, 0.000000000000001, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -0, 2**53+2, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE]); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 24 != 0) }));}/*iii*/;");
/*fuzzSeed-209835301*/count=1175; tryItOut("v0 = g0.runOffThreadScript();");
/*fuzzSeed-209835301*/count=1176; tryItOut("const iagpoa, [] = true, x, y = (Math.min(-1, /\\w/yim)), vstnll, x = new WeakSet(), [] = (eval(\"/* no regression tests found */\",  /x/ )), x, x, zlcynp;/* no regression tests found */");
/*fuzzSeed-209835301*/count=1177; tryItOut("h1 + this.i0;");
/*fuzzSeed-209835301*/count=1178; tryItOut("f1 = (function mcc_() { var pigzyw = 0; return function() { ++pigzyw; this.f1(/*ICCD*/pigzyw % 9 == 4);};})();");
/*fuzzSeed-209835301*/count=1179; tryItOut("x = x & x; var r0 = 4 | x; var r1 = 5 + x; var r2 = r1 + r1; var r3 = r2 % r0; var r4 = r1 - 0; var r5 = 3 / r2; var r6 = r3 ^ r3; var r7 = r1 | 9; var r8 = r4 & 1; var r9 = r2 | r2; var r10 = r7 / 8; var r11 = 3 % r5; r5 = r7 % r0; var r12 = r6 | 5; r8 = r6 * 6; var r13 = r2 / r12; var r14 = r2 | 8; var r15 = 3 / r8; r3 = r13 | r11; print(r1); var r16 = x / 5; var r17 = r12 & r9; r17 = r2 % 5; var r18 = r8 % 0; var r19 = r14 / r5; r9 = r6 & 9; var r20 = 3 ^ 5; print(r9); r7 = 2 % r2; r17 = r6 + 8; var r21 = 9 ^ r12; var r22 = 6 + r18; print(r1); var r23 = r7 ^ 5; var r24 = r0 | 5; var r25 = 1 | r6; var r26 = 2 | 6; r26 = r26 % r18; var r27 = 9 % x; var r28 = 5 * 7; r26 = 6 / 6; var r29 = r7 % r7; var r30 = 8 & r8; r22 = 2 & 1; var r31 = r24 ^ 5; var r32 = 3 % r28; var r33 = r7 / 1; var r34 = 6 ^ r4; var r35 = r31 - 9; r12 = 0 ^ r2; print(r27); var r36 = r19 & r27; var r37 = r1 + r18; var r38 = r3 | 9; r15 = r35 % r17; r15 = r25 | r25; var r39 = r35 & r12; var r40 = 3 | 6; r37 = r38 ^ r10; var r41 = r18 ^ r29; var r42 = 0 ^ r31; var r43 = r35 * r1; var r44 = r17 - r6; r9 = r18 / r25; r5 = x - r31; var r45 = r42 | 3; var r46 = 5 / r24; var r47 = r6 | r13; var r48 = r42 | r15; var r49 = r45 | 5; var r50 = r22 % r45; var r51 = 3 | r17; var r52 = x * 1; var r53 = r5 + r10; var r54 = r19 * 2; var r55 = r38 - 5; var r56 = 9 | r50; var r57 = 0 ^ r44; var r58 = r10 - r18; r36 = r51 + 9; var r59 = r7 % r30; var r60 = 1 + 4; r26 = 9 * r4; var r61 = r47 % 5; r19 = 1 & r48; var r62 = r13 - r50; var r63 = r20 % 2; r47 = r37 | r31; var r64 = 2 - 6; var r65 = r41 ^ r9; var r66 = r54 + r63; var r67 = 1 & r51; r28 = r56 ^ r59; print(r58); r3 = r51 & r64; var r68 = 1 + r48; r25 = r51 + r30; var r69 = 7 + r56; var r70 = r27 ^ r0; var r71 = r55 & r69; var r72 = r9 ^ r45; var r73 = 5 * r70; var r74 = r17 * 8; var r75 = r48 & r39; var r76 = r57 - r12; var r77 = 3 % r7; var r78 = 8 & r46; var r79 = 5 | 5; var r80 = 4 ^ r8; var r81 = r57 % 4; var r82 = r57 & r53; r37 = r74 / r48; var r83 = r61 * r72; var r84 = r78 + r25; r7 = 8 + r73; var r85 = 0 * 9; var r86 = 5 ^ r10; r60 = 0 & 8; var r87 = r4 - r27; var r88 = 4 - r46; r1 = r78 & 1; var r89 = 1 * r69; var r90 = 7 & 2; var r91 = r87 * 8; r34 = r26 ^ r56; var r92 = r7 % r16; var r93 = r70 % r67; var r94 = 4 | r11; var r95 = r8 * 1; var r96 = r7 + 6; r7 = r60 / 0; r42 = r29 * 2; var r97 = 6 + 7; var r98 = 4 % 7; var r99 = 7 - 9; var r100 = 8 ^ r51; r53 = 0 / r18; var r101 = r95 | 6; var r102 = r35 % 5; r88 = r88 & 3; var r103 = r79 * 4; var r104 = r86 | 8; var r105 = r94 - 1; var r106 = r28 - 8; r50 = 9 + r30; var r107 = r103 | 7; var r108 = 0 - 5; var r109 = r4 % 6; var r110 = 3 % 1; r89 = 5 ^ r15; var r111 = r76 * r85; var r112 = 8 ^ r101; print(r110); var r113 = 0 / r50; var r114 = 4 * 6; var r115 = r72 % r5; var r116 = r40 % r38; var r117 = r9 & r82; r22 = 5 - r64; var r118 = 4 - 7; r53 = r36 | r56; var r119 = r99 / r32; r80 = r55 & 9; r94 = 8 * r3; r69 = 0 | r33; r63 = r73 ^ r97; var r120 = r83 / 5; var r121 = r7 / r62; r86 = r15 % r75; var r122 = r78 % 3; var r123 = r91 / r97; r15 = 4 * 5; var r124 = r87 / r87; r61 = r38 * r41; var r125 = r17 - r92; var r126 = r92 * r27; var r127 = 7 ^ 1; var r128 = 5 * 7; r5 = 1 & r36; r83 = 8 & r6; var r129 = r69 - r84; var r130 = r22 + 6; var r131 = 4 | r127; r65 = r88 % r125; print(r2); r55 = r68 | r129; var r132 = r82 % 7; r72 = r51 / r34; var r133 = r69 / 9; var r134 = r34 * r77; var r135 = 0 * 1; var r136 = 7 ^ r68; var r137 = r112 ^ r103; print(r35); r14 = r29 % r10; r39 = r114 | r57; var r138 = 4 | 0; var r139 = r123 | r9; var r140 = 0 + r68; var r141 = r74 - 3; var r142 = r104 | r76; var r143 = r107 / r13; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1180; tryItOut("mathy4 = (function(x, y) { return ( + (((Math.fround(Math.max(( + ( ! Math.sin(( + x)))), Math.fround(Math.fround(Math.hypot(Math.fround(y), Math.fround(Math.log10(x))))))) | 0) ? ((( + Math.fround(x)) >>> ( + ((( ! (y >>> 0)) >>> 0) | ( + (-0x080000000 | (( ~ (x >>> 0)) >>> 0)))))) | 0) : ( + Math.fround(Math.min(Math.fround((Math.log2(x) << ( ! Math.fround(Math.asinh(y))))), ((((Math.sqrt(-0x080000000) >>> 0) != (x >>> 0)) | 0) >>> 0))))) | 0)); }); testMathyFunction(mathy4, [0, ({toString:function(){return '0';}}), (new Boolean(true)), [0], (function(){return 0;}), ({valueOf:function(){return '0';}}), [], NaN, objectEmulatingUndefined(), -0, '', ({valueOf:function(){return 0;}}), 0.1, null, (new Number(-0)), 1, (new Number(0)), (new String('')), false, true, (new Boolean(false)), /0/, undefined, '/0/', '0', '\\0']); ");
/*fuzzSeed-209835301*/count=1181; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy1((Math.pow((( + Math.imul(y, ( + ((Math.sign((y | 0)) ? Math.fround(( + -Number.MIN_SAFE_INTEGER)) : 0x080000001) | 0)))) == -(2**53-2)), ( + y)) >>> 0), ((Math.log1p(((mathy0((Math.atan2(Math.atan2((( - Math.cosh(y)) >>> 0), x), Math.expm1(x)) >>> 0), (Math.atanh(Math.fround(( ~ (mathy2(Math.log2(x), ((42 ** x) | 0)) | 0)))) >>> 0)) >>> 0) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [NaN, (new String('')), ({valueOf:function(){return '0';}}), -0, ({valueOf:function(){return 0;}}), 1, '/0/', 0.1, [0], (new Boolean(false)), (new Boolean(true)), (new Number(0)), false, true, 0, /0/, '\\0', null, undefined, (function(){return 0;}), ({toString:function(){return '0';}}), '', [], (new Number(-0)), '0', objectEmulatingUndefined()]); ");
/*fuzzSeed-209835301*/count=1182; tryItOut("\"use strict\"; function shapeyConstructor(uuhdvq){uuhdvq[\"valueOf\"] = window;Object.seal(uuhdvq);uuhdvq[\"wrappedJSObject\"] = true;{ i1.send(i2); } uuhdvq[\"wrappedJSObject\"] = new Number(1);for (var ytqzhcyzb in uuhdvq) { }for (var ytqoeiekk in uuhdvq) { }if ((this.__defineGetter__(\"d\", offThreadCompileScript))) uuhdvq[\"wrappedJSObject\"] = (x);return uuhdvq; }/*tLoopC*/for (let b of /*FARR*/[.../*MARR*/[Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity,  \"\" , objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity,  \"\" , function(){}, Infinity, function(){}], Math.imul(-12, -22), x, .../*FARR*/[.../*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), new Number(1), (1/0), new String('q'), new String('q'), new String('q'), new String('q'), (1/0), new String('q'), new Number(1), (1/0), (1/0), new Number(1), new String('q'), new Number(1), new String('q'), new String('q'), new Number(1), new String('q'), new String('q'), new String('q'), new String('q'), new Number(1), (1/0), (1/0), (1/0), new String('q'), (1/0), new String('q'), new String('q'), new Number(1), new String('q'), (1/0), new Number(1), (1/0), (1/0), (1/0), new Number(1), new String('q'), new String('q'), new Number(1), new Number(1), new String('q'), (1/0), new String('q'), new Number(1), (1/0), (1/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (1/0), (1/0), new Number(1), (1/0), (1/0), (1/0), new Number(1), (1/0), new Number(1), new String('q')], .../*MARR*/[undefined, ({}), ({}), undefined, undefined, (-0), undefined, (-0), (-0), ({}), ({}), ({}), (-0), (-0), (-0), undefined, ({}), (-0), ({}), undefined, ({}), undefined, ({}), (-0), undefined, (-0), ({}), (-0), undefined, (-0), ({}), undefined, (-0), undefined, undefined, (-0), (-0), (-0), undefined, undefined, undefined, undefined, ({}), (-0)]], .../*PTHR*/(function() { for (var i of /*FARR*/[({ set big(NaN, e = window, x, x, d, a, y) { yield  /x/g  } , indexOf: true })]) { yield i; } })(), x = Proxy.createFunction(({/*TOODEEP*/})(\"\\u6050\"), decodeURI)]) { try{let iuvtab = shapeyConstructor(b); print('EETT'); Date.prototype.getYear}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-209835301*/count=1183; tryItOut("\"use strict\"; let(y) ((function(){this.zzz.zzz;})());let(NaN = (4277).yoyo(let (c) c), sitwxz, eval =  \"\" , darezn, window =  \"\" , swdjio) { let(w =  /x/ .apply(), sqsxxz, e = x, a = z, y, x) { return;}}");
/*fuzzSeed-209835301*/count=1184; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.imul(( + ( ! Math.fround((Math.fround(y) & Math.fround(x))))), (Math.max(Math.pow((-0x080000000 == ( + Math.pow(1.7976931348623157e308, x))), (y & x)), 42) >>> 0))); }); testMathyFunction(mathy4, [0x080000001, -1/0, -Number.MAX_VALUE, -0x080000000, -0x100000001, 1.7976931348623157e308, -(2**53-2), 0x100000001, Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -0x100000000, -0x080000001, 0x100000000, Number.MAX_VALUE, -0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, Math.PI, -(2**53+2), 1, -0x0ffffffff, -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, 0, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -(2**53), 2**53+2]); ");
/*fuzzSeed-209835301*/count=1185; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0((((Math.fround(Math.clz32(Math.fround((( - (Math.PI >>> 0)) >>> 0)))) >>> 0) > (( + ( + Math.fround(y))) >>> 0)) >>> 0), ((( ~ (Math.fround(mathy0(Math.fround(Math.asin((x | 0))), Math.fround(x))) <= ( ! x))) | 0) + Math.min((( + ( - ( + ( + ( - x))))) >>> 0), Math.fround(Math.log10((x >>> 0)))))); }); testMathyFunction(mathy2, ['', -0, '0', (new Boolean(false)), (new Number(-0)), '\\0', /0/, undefined, (new String('')), null, (new Number(0)), ({toString:function(){return '0';}}), [0], ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(true)), '/0/', NaN, ({valueOf:function(){return 0;}}), true, 0.1, 0, false, 1, (function(){return 0;}), []]); ");
/*fuzzSeed-209835301*/count=1186; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.exp((Math.imul(Math.min(Math.hypot(2**53, ( ! (-(2**53+2) && y))), (( ! (y >>> 0)) >>> 0)), ( + Math.pow(Math.min(Math.fround(Math.acosh(Math.fround(x))), Math.log2(y)), ( + ( - ( + (Math.fround(y) ? Math.fround(y) : Math.fround(Math.hypot(x, y))))))))) >>> 0)); }); testMathyFunction(mathy2, [-(2**53), 1.7976931348623157e308, -1/0, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, 0x080000000, -0, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 42, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), Number.MIN_VALUE, 0x080000001, Math.PI, 0, 1, -0x0ffffffff, 0x100000000, Number.MAX_VALUE, -0x080000001, 0/0]); ");
/*fuzzSeed-209835301*/count=1187; tryItOut("this.h0 = {};");
/*fuzzSeed-209835301*/count=1188; tryItOut("var amcfwo = new SharedArrayBuffer(0); var amcfwo_0 = new Int16Array(amcfwo); print(amcfwo_0[0]); amcfwo_0[0] = -5; var amcfwo_1 = new Float32Array(amcfwo); amcfwo_1[0] = 17; var amcfwo_2 = new Int16Array(amcfwo); amcfwo_2[0] = x; var amcfwo_3 = new Uint32Array(amcfwo); var amcfwo_4 = new Uint8ClampedArray(amcfwo); amcfwo_4[0] = -2; var amcfwo_5 = new Uint8Array(amcfwo); var amcfwo_6 = new Uint16Array(amcfwo); var amcfwo_7 = new Uint16Array(amcfwo); amcfwo_7[0] = 2; /*infloop*/ for  each(let arguments.callee.arguments in amcfwo_0[0]) for (var v of b0) { try { i1 + m2; } catch(e0) { } try { for (var v of g2) { try { s0 += s0; } catch(e0) { } try { t1[v2]; } catch(e1) { } try { a1 = a0.slice(0, 4, ({a2:z2})); } catch(e2) { } v2 = a0.length; } } catch(e1) { } try { this.v1 = t0.length; } catch(e2) { } Array.prototype.unshift.call(a0, m0, b1, t1); }this.a2[arguments[\"values\"]++] = o2.o0.b1;M:for(let e in \u3056) print( \"\" );");
/*fuzzSeed-209835301*/count=1189; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1190; tryItOut("e2.has(b2);");
/*fuzzSeed-209835301*/count=1191; tryItOut("t0 = t0.subarray(3);");
/*fuzzSeed-209835301*/count=1192; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.sinh((Math.pow((( + (( + (Math.fround(( + ((y / x) >>> 0))) % Math.fround(( + (( ! -1/0) ? mathy0(y, x) : ( + x)))))) / ( + x))) | 0), (((Math.fround(-(2**53-2)) ? Math.min(y, x) : Math.fround((((x >>> 0) ** (( + ( + x)) >>> 0)) >>> 0))) / Math.fround(Math.hypot(Math.fround(y), y))) | 0)) | 0)) | 0) - Math.fround((Math.atanh(( + ((Math.pow(Math.fround(-Number.MAX_SAFE_INTEGER), (y >>> 0)) >>> 0) ? (mathy0((x >>> 0), ( - mathy0(( + y), y))) | 0) : Math.fround(x)))) | (Math.fround(( + Math.fround(y))) >>> 0)))); }); testMathyFunction(mathy1, [-(2**53+2), Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -0x100000000, -(2**53), 2**53-2, 0/0, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -0x07fffffff, 0x100000000, -0, 1, -0x0ffffffff, 2**53+2, 0x080000000, -0x080000001, Number.MAX_SAFE_INTEGER, 0, -0x100000001, 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, -(2**53-2), 2**53, -1/0]); ");
/*fuzzSeed-209835301*/count=1193; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.atan2(Math.pow(mathy2(Math.fround(Math.cosh(x)), Math.fround((Math.tanh(((( + ((x >>> 0) > 0x07fffffff)) >= Math.fround(Math.log2(x))) >>> 0)) >>> 0))), (( + (( + x) >>> 0)) | 0)), ( + Math.fround(( + Math.fround(Math.fround(Math.ceil(Math.fround(( + Math.ceil(( + (( + y) ** ( + mathy0((y ? (x >>> 0) : x), x)))))))))))))); }); ");
/*fuzzSeed-209835301*/count=1194; tryItOut("\"use strict\"; M:if((x % 18 != 10)) this.o1.toString = (function() { for (var j=0;j<11;++j) { f2(j%3==0); } }); else  if (false) {o1 = h1.__proto__; }");
/*fuzzSeed-209835301*/count=1195; tryItOut("mathy5 = (function(x, y) { return ( - ( ! (mathy4((Math.min(x, (mathy3((( + 0x07fffffff) >>> 0), (x >>> 0)) >>> 0)) >>> 0), ((Math.asin(0/0) >= (Math.asin((Math.min(((Math.imul((-Number.MAX_SAFE_INTEGER | 0), (-Number.MAX_VALUE | 0)) | 0) | 0), (Math.round(Number.MAX_VALUE) | 0)) | 0)) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [0x080000000, -1/0, -0x100000000, -(2**53+2), -0x0ffffffff, 0, 42, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, Math.PI, 1.7976931348623157e308, 0/0, -0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -0x080000001, 0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0, 2**53, 1, 0x07fffffff, Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-209835301*/count=1196; tryItOut("/*ADP-3*/Object.defineProperty(a1, 12, { configurable: (x % 4 == 3), enumerable: (x % 9 != 3), writable: true, value: this.o0 });");
/*fuzzSeed-209835301*/count=1197; tryItOut("mathy1 = (function(x, y) { return mathy0((( + (( + Math.sinh((x | 0))) ? ( + (((((( + ( - ( ! y))) >>> (y | 0)) | 0) >>> 0) && (Math.acos(( + (x ^ ( + x)))) >>> 0)) >>> 0)) : ( + (Math.atan((y | 0)) | 0)))) | 0), ( + Math.log1p(( + ( - (0x100000001 >>> 0)))))); }); testMathyFunction(mathy1, [0.000000000000001, 1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, 0, 2**53, 2**53-2, Math.PI, 0x100000000, -1/0, Number.MIN_VALUE, Number.MAX_VALUE, 1, 0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 0x100000001, -0x080000001, -0x100000001, -0x100000000, 42, Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, -(2**53), -(2**53+2), -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-209835301*/count=1198; tryItOut("\"use strict\"; print(x);function \u0009x() { return 2 } v1 = Object.prototype.isPrototypeOf.call(f2, e1);\na1.push(f2);\n");
/*fuzzSeed-209835301*/count=1199; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.fround(Math.pow((Math.imul((Math.atan2(((Math.acos(42) ? 0 : (x / y)) >>> 0), -Number.MIN_SAFE_INTEGER) >>> 0), (Math.imul((x | 0), ((Math.fround(Math.exp(y)) >>> 0) | 0)) | 0)) | 0), Math.fround((((Math.imul(-Number.MIN_VALUE, y) >>> 0) | 0) == (Math.max(y, ( + y)) >>> 0)))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, 1, 1.7976931348623157e308, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 42, 0x080000001, Math.PI, 2**53, -0x100000000, 0x0ffffffff, -0x100000001, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, -0, Number.MAX_VALUE, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, -(2**53), 2**53-2, -1/0, -0x0ffffffff, 1/0, 0/0]); ");
/*fuzzSeed-209835301*/count=1200; tryItOut("\"use strict\"; let x = (yield (({NaN: \"\\u6CF2\"})));b2.__proto__ = i0;");
/*fuzzSeed-209835301*/count=1201; tryItOut("mathy0 = (function(x, y) { return ( + Math.sin(Math.hypot((Math.sign(((y || Number.MAX_VALUE) >>> 0)) >>> 0), x))); }); testMathyFunction(mathy0, [-(2**53), -(2**53+2), 0.000000000000001, 0x080000001, -1/0, -(2**53-2), -0x100000000, 1/0, Number.MAX_VALUE, 0x07fffffff, Math.PI, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, -0, 1, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, -0x080000000, 0x100000000, 0/0, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, 0x080000000, 2**53, 0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=1202; tryItOut("\"use strict\"; M:\u000cif((this.__defineGetter__(\"y\", Math.tanh(-5)))) {for (var v of i2) { m2.delete(this.zzz.zzz = ((function a_indexing(owyoxr, wjlzes) { ; if (owyoxr.length == wjlzes) { ; return yield /[^]|(?:\\u826d)|[^]{1}(?:\\B|(?=[\\S\u37cf\\u00e8\\u0042])|(?=\u77dc)){16,}*/ym; } var ttygjv = owyoxr[wjlzes]; var wyswwr = a_indexing(owyoxr, wjlzes + 1); g0.h1 = {}; })(/*MARR*/[ 'A' , \"\\u840E\",  'A' ,  'A' , x,  'A' , new Number(1),  'A' , \"\\u840E\", \"\\u840E\", x, x,  'A' , x,  'A' , x,  'A' , x, \"\\u840E\", x, \"\\u840E\", x, \"\\u840E\",  'A' , \"\\u840E\",  'A' , new Number(1), x,  'A' , x,  'A' , x, \"\\u840E\", \"\\u840E\", new Number(1), x, new Number(1),  'A' , new Number(1),  'A' ,  'A' , \"\\u840E\", x, new Number(1), \"\\u840E\",  'A' , \"\\u840E\", new Number(1), \"\\u840E\",  'A' , \"\\u840E\",  'A' ,  'A' , x, x, x, x, x,  'A' , \"\\u840E\", x, \"\\u840E\",  'A' , x, new Number(1), new Number(1), \"\\u840E\", \"\\u840E\",  'A' , \"\\u840E\",  'A' ,  'A' , \"\\u840E\", new Number(1), new Number(1),  'A' ,  'A' ,  'A' , \"\\u840E\"], 0))); } for  each(var a in x) {a2.toString = (function mcc_() { var vbtmvd = 0; return function() { ++vbtmvd; this.f0(/*ICCD*/vbtmvd % 8 != 6);};})();var i1 = new Iterator(s1); } } else  if (x+=let (y) Math.atan2(29, (makeFinalizeObserver('tenured')))) v1 = b1.byteLength;\ne0.has(b2);\nh1 = x;\n\n");
/*fuzzSeed-209835301*/count=1203; tryItOut("mathy3 = (function(x, y) { return Math.fround((Math.fround(( ~ ( - ((y | 0) / (y | 0))))) , Math.expm1(( - Math.fround(y))))); }); ");
/*fuzzSeed-209835301*/count=1204; tryItOut("var b = (4277);this.h2.delete = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i1);\n    }\n    return +((((16384.0)) - ((+(0.0/0.0)))));\n  }\n  return f; })(this, {ff: (new Function(\"Object.defineProperty(this, \\\"v1\\\", { configurable: false, enumerable: (x % 2 != 0),  get: function() {  return 4; } });\"))}, new ArrayBuffer(4096));");
/*fuzzSeed-209835301*/count=1205; tryItOut("\"use strict\"; window;function window((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: mathy1, defineProperty: function(){}, getOwnPropertyNames: Promise, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: String.prototype.trimLeft, keys: undefined, }; })(let (y =  /x/ ) /\\B|(?:(?=\\u0022*))|(^+)/gim), x) { delete h1.keys; } v0 = new Number(m2);");
/*fuzzSeed-209835301*/count=1206; tryItOut("/*RXUB*/var r = /(?![\\D\\xEa][\udf97\\\ue15a]|[^]\\B(?:(\\b))|(?!(?!\\2))*)((?=(?!(?:$|[^]*?)?)))+?/gyim; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-209835301*/count=1207; tryItOut("");
/*fuzzSeed-209835301*/count=1208; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v2, g0.p2);");
/*fuzzSeed-209835301*/count=1209; tryItOut("\"use strict\"; r0 = /(?=\\3?(?:[^])|(?=.)|\\cC)*?|$(?!\\B)+?*?/im;");
/*fuzzSeed-209835301*/count=1210; tryItOut("this.m2 = m0.get(g2.f2);");
/*fuzzSeed-209835301*/count=1211; tryItOut("v1 = evaluate(\"function f2(v2)  { yield (makeFinalizeObserver('nursery')) } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-209835301*/count=1212; tryItOut("\"use strict\"; v1 = a2[\"arguments\"];");
/*fuzzSeed-209835301*/count=1213; tryItOut("f0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -70368744177665.0;\n    {\n      return (((i0)))|0;\n    }\n    d2 = (+(1.0/0.0));\n    switch ((((1)) >> (((0xd2d7ebe) > (0x3db25e46))-((0x43af977e))))) {\n      case -2:\n        i0 = ((((((((((0xfd7b7f5e)) | ((0x53c22c6))))*0xa29e8)|0))+(!(i0))-(i1)) >> (((((((0x1a7d7527)) & ((0x61f53bff)))))>>>((0xffffffff)+(0x419c3354)-(0x3864e244))) / ((-((0x655c613c) > (-0x8000000)))>>>((0x60b73828)*0x78cb7)))) > ((((0xaab34414))) & ((0xd12e5e7f))));\n        break;\n      case 1:\n        d2 = (d2);\n        break;\n      case 0:\n        {\n          return (((i0)))|0;\n        }\n      case -2:\n        i0 = ((abs((~((i0)+(0xfeb12a46)+(!(0xfb5f90b4)))))|0) < (~((i0)-(-0x8000000))));\n      case -2:\n        i1 = (0xfa518782);\n        break;\n      default:\n        i0 = (i1);\n    }\n    (Uint8ArrayView[((0x57cf8e53)-(0xfce495df)+(0xffffffff)) >> 0]) = ((i0)+(!(i0)));\n    d2 = (-1048577.0);\n    {\n      {\n        (Int16ArrayView[4096]) = ((((i0)+((((-0x8000000)) ^ ((0xffb3c561))) != (((0xc259e56f)) | ((0xa062c97e))))-(!((((0x6e823ab5))>>>((0xffffffff))) <= (((0x5ccc26f8))>>>((-0x8000000)))))) ^ ((i0)-((-0x8000000) ? (i0) : ((0xe897956))))) % (((((!(0x2f919445))) | (((137438953472.0) != (-18446744073709552000.0)))) / (((allocationMarker())) | ((i1)*0x37470))) ^ ((i1)+((imul((i1), ((Int8ArrayView[((0xf8894479)-(0xfea4db46)) >> 0])))|0)))));\n      }\n    }\n    return (((i0)-((d2) != (-70368744177663.0))-(0xfee85fc9)))|0;\n    {\n      (Uint8ArrayView[0]) = (((0x3576ee52)));\n    }\n    switch ((this.__defineSetter__(\"x\", (function shapeyConstructor(mfrhcy){\"use strict\"; delete this[\"call\"];for (var ytqirhngp in this) { }this[\"arguments\"] = x;this[\"fill\"] = new RegExp(\"(?:^)\", \"i\");this[\"fill\"] =  \"\" ;this[\"call\"] = window;if ( /x/ ) this[\"fill\"] =  /x/g ;for (var ytqstywcx in this) { }return this; }).apply))) {\n      case -2:\n        (Uint16ArrayView[2]) = ((!(i0)));\n      case -3:\n        d2 = (+pow(((-0.5)), ((+(1.0/0.0)))));\n        break;\n    }\n    return (((0xcff8d2c8)))|0;\n  }\n  return f; });");
/*fuzzSeed-209835301*/count=1214; tryItOut("mathy4 = (function(x, y) { return (Math.min(( ~ (2**53+2 ? ( + (( ~ y) == Math.fround(Math.max(Math.fround(x), Math.fround(y))))) : (0x080000000 >= mathy1(x, ((y >>> 0) ^ Math.fround(x)))))), mathy2((( - (( + Math.tan((((x | 0) ? x : (x | 0)) | 0))) | 0)) | 0), Math.imul(( + ((((( + (( + y) || ( + Math.fround((y << y))))) | 0) >>> (Math.atan(y) | 0)) | 0) / ( + y))), (Math.cos(( + y)) >>> 0)))) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[new Number(1.5), new String(''), new Number(1.5), new String(''), new String(''), new Number(1.5), new String(''), new String(''), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), new Number(1.5), new String(''), new Number(1.5), new String(''), new String(''), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), new String(''), new Number(1.5), new String(''), new String(''), new Number(1.5), new Number(1.5), new String(''), new String('')]); ");
/*fuzzSeed-209835301*/count=1215; tryItOut("mathy1 = (function(x, y) { return mathy0(((((((( - (y | 0)) | 0) != ( + Math.fround(( ! Math.atan(( ~ y)))))) | 0) ? (((( ! Math.min(x, Math.min((42 >>> 0), (x >>> 0)))) | 0) ** (mathy0(y, Math.acosh(x)) | 0)) | 0) : (mathy0((( ~ (Math.min(y, y) / -Number.MAX_VALUE)) >>> 0), ( + ( + (Math.asin(Math.fround((0x0ffffffff >= x))) >>> 0)))) >>> 0)) | 0) >>> 0), (Math.imul((mathy0((Math.cbrt(y) | 0), ( + Math.sinh(Math.fround(y)))) | 0), (Math.tan(((Math.fround(x) | (y >>> 0)) >>> 0)) | 0)) || ( ~ y))); }); ");
/*fuzzSeed-209835301*/count=1216; tryItOut("a1.splice(NaN, 14);");
/*fuzzSeed-209835301*/count=1217; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1218; tryItOut("\"use strict\"; a2.shift(t2);");
/*fuzzSeed-209835301*/count=1219; tryItOut("M:if(false) {((4277)); } else {t1 + '';i0.__proto__ = f1; }");
/*fuzzSeed-209835301*/count=1220; tryItOut("\"use strict\"; { void 0; verifyprebarriers(); } v2 = b2.byteLength;");
/*fuzzSeed-209835301*/count=1221; tryItOut("mathy3 = (function(x, y) { return ( + (Math.hypot(Math.fround(Math.pow(Math.fround((Math.fround(Math.sin(x)) & ( ~ x))), ( + 0x100000000))), Math.fround(Math.fround((Math.fround(Math.atanh(( + x))) >>> Math.fround(0x07fffffff))))) ? ( + Math.asinh(Math.fround(Math.imul((-0x080000000 | 0), ( + 0x080000001))))) : mathy0(Math.pow(( + Math.cosh(((y >>> 0) ? x : x))), Math.fround((Math.imul(x, x) >>> 0))), Math.fround(( ~ x))))); }); ");
/*fuzzSeed-209835301*/count=1222; tryItOut("testMathyFunction(mathy4, [Number.MIN_VALUE, 0, 2**53-2, -(2**53-2), 1, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -0, Math.PI, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53, 42, -(2**53), -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, -0x080000000, 0/0, 0x080000001, 0x07fffffff, 0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -0x100000000, -0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1223; tryItOut("t0[({valueOf: function() { v2 = evaluate(\"function f1(o2.m0)  { \\\"use strict\\\"; print(x); } \", ({ global: o1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x)(), catchTermination: yield x }));return 4; }})] = function  x (x) { o1.e1.valueOf = (function mcc_() { var xwjata = 0; return function() { ++xwjata; if (/*ICCD*/xwjata % 5 == 3) { dumpln('hit!'); [,] = g1.t0[({valueOf: function() { i0 = a2.iterator;return 10; }})]; } else { dumpln('miss!'); try { t1.set(g2.a2, 0); } catch(e0) { } Object.prototype.watch.call(p0, new String(\"-1\"), (function mcc_() { var nhzxzb = 0; return function() { ++nhzxzb; if (/*ICCD*/nhzxzb % 8 == 4) { dumpln('hit!'); try { e2 + ''; } catch(e0) { } try { g1[\"wrappedJSObject\"] = a2; } catch(e1) { } try { h2.getPropertyDescriptor = (function(stdlib, foreign, heap){ \"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float64ArrayView[((0x269f9d27)) >> 3]) = ((2147483649.0));\n    return +((3.8685626227668134e+25));\n  }\n  return f; }); } catch(e2) { } h0.getPropertyDescriptor = (function() { try { s1 = this.a1.join(this.g0.g2.s0, b1); } catch(e0) { } try { v0 = 4; } catch(e1) { } try { neuter(b0, \"change-data\"); } catch(e2) { } v2 = evaluate(\"g2.a0 + o0.g2;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 1), noScriptRval: (x % 95 != 79), sourceIsLazy: (x % 80 == 16), catchTermination: true, elementAttributeName: s1, sourceMapURL: g2.s0 })); return t1; }); } else { dumpln('miss!'); Array.prototype.forEach.apply(a0, [(function() { try { a2.__proto__ = s0; } catch(e0) { } try { Array.prototype.pop.apply(a1, []); } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(h0, i0); } catch(e2) { } s1 = this.a0; throw m2; }),  '' , v2, e2, f2, s2, e2, p0]); } };})()); } };})(); } .prototype;");
/*fuzzSeed-209835301*/count=1224; tryItOut("\"use strict\"; Array.prototype.unshift.call(a2, b1, o0, this.g0, timeout(1800));");
/*fuzzSeed-209835301*/count=1225; tryItOut("Array.prototype.push.call(o1.a0, g1);t0 + this.e0;");
/*fuzzSeed-209835301*/count=1226; tryItOut("/*hhh*/function fvfexb(...e){i1.next();}fvfexb(((y = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(this), (eval).call)) = x));");
/*fuzzSeed-209835301*/count=1227; tryItOut("\"use strict\"; x |= x;function x()\"use asm\";   var pow = stdlib.Math.pow;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = (0xfc781600);\n    {\n      d1 = (-1048577.0);\n    }\n    {\n      (Float32ArrayView[((i2)) >> 2]) = ((((36893488147419103000.0)) % ((+pow((((6.044629098073146e+23) + (9.671406556917033e+24))), ((+(1.0/0.0))))))));\n    }\n    i2 = (i2);\n    return +((-36028797018963970.0));\n  }\n  return f;yield;");
/*fuzzSeed-209835301*/count=1228; tryItOut("\"use strict\"; Object.freeze(g2);function \u3056(this.zzz.zzz, x) { L:with(Object.defineProperty(x, \"wrappedJSObject\", ({}))){selectforgc(o1);/*RXUB*/var r = /\\2/gy; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex);  } } for (var v of o2.g2.s0) { v2 = (g2.m1 instanceof g0.o0); }");
/*fuzzSeed-209835301*/count=1229; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.asin(( - ( ~ (( + (((Math.fround(y) , x) * x) >>> 0)) | 0)))); }); testMathyFunction(mathy1, [Math.PI, Number.MAX_SAFE_INTEGER, -(2**53-2), 1, 0x080000000, -0x100000000, 42, 0x100000000, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, 0, -Number.MIN_VALUE, -0x0ffffffff, -0, -1/0, Number.MAX_VALUE, -0x080000000, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, 1/0, -(2**53+2), 0x100000001, -(2**53), 0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-209835301*/count=1230; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2{0,4}/gy; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-209835301*/count=1231; tryItOut("/*RXUB*/var r = r1; var s = (4277); print(r.exec(s)); ");
/*fuzzSeed-209835301*/count=1232; tryItOut(" \"\" ;");
/*fuzzSeed-209835301*/count=1233; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?:\\b*)*)*|((?:(?=[](?:[^\\ucF81\\r-\uca3a\\d]){2,})))+/i; var s = \"\"; print(s.split(r)); print(r.lastIndex); /* no regression tests found */");
/*fuzzSeed-209835301*/count=1234; tryItOut("\"use strict\"; for (var p in o2) { Object.defineProperty(o2, \"v2\", { configurable: true, enumerable: true,  get: function() {  return b2[\"call\"]; } }); }");
/*fuzzSeed-209835301*/count=1235; tryItOut("o2.g0.a0.length = 19;");
/*fuzzSeed-209835301*/count=1236; tryItOut("\"use strict\"; testMathyFunction(mathy3, [42, 1, 0/0, Number.MAX_SAFE_INTEGER, Math.PI, -1/0, -Number.MAX_VALUE, -0x07fffffff, 1/0, Number.MAX_VALUE, -(2**53-2), 0x100000000, 0x07fffffff, -0x100000000, Number.MIN_VALUE, 0x080000001, 2**53+2, -Number.MIN_VALUE, 0x100000001, 0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 2**53, -0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 2**53-2, -0x100000001, -0]); ");
/*fuzzSeed-209835301*/count=1237; tryItOut("\"use strict\"; Array.prototype.unshift.call(a2, s1, h0, o1, i0, b0);");
/*fuzzSeed-209835301*/count=1238; tryItOut("mathy1 = (function(x, y) { return Math.hypot(Math.fround(((Math.fround(Math.min(( + Math.max((Math.fround((Math.fround(y) || y)) | 0), ((((x < x) == (y >>> 0)) >>> 0) | 0))), Math.fround((x ? x : x)))) | 0) >= (Math.fround((( + mathy0(-0x080000000, x)) ? Math.fround((Math.imul((-Number.MAX_SAFE_INTEGER | 0), Math.fround(( + Math.fround(y)))) >>> 0)) : Math.fround(( + ( ~ mathy0(Math.fround(x), x)))))) == ( + Math.atan2(Math.fround(y), Math.fround(((y | 0) ? y : 1.7976931348623157e308))))))), Math.atan((Math.max((((y >>> 0) != y) | 0), (( + Math.tanh(( ! y))) | 0)) >>> 0))); }); testMathyFunction(mathy1, [0/0, Number.MAX_VALUE, -(2**53+2), 0x100000001, -0, 42, Number.MIN_VALUE, Math.PI, 1, -(2**53-2), -(2**53), 1.7976931348623157e308, 0x0ffffffff, 1/0, -0x100000001, -0x080000001, 2**53, 0.000000000000001, 2**53-2, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 0x080000001, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 2**53+2, 0x080000000, 0x100000000]); ");
/*fuzzSeed-209835301*/count=1239; tryItOut("const x;\u000c(\"\\u76B5\");\ns1 += s1;\n");
/*fuzzSeed-209835301*/count=1240; tryItOut("t0 = t2.subarray(v1);");
/*fuzzSeed-209835301*/count=1241; tryItOut("print(((d =  '' )));\nArray.prototype.splice.apply(a0, [NaN, ({valueOf: function() { v0 = (o2.s2 instanceof p0);return 11; }})]);\n");
/*fuzzSeed-209835301*/count=1242; tryItOut("i1.__iterator__ = f2;");
/*fuzzSeed-209835301*/count=1243; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.split(r)); print(Infinity);");
/*fuzzSeed-209835301*/count=1244; tryItOut("\"use strict\"; g1.toString = (function() { for (var v of m2) { f2.toString = f2; } return p0; });");
/*fuzzSeed-209835301*/count=1245; tryItOut("\"use strict\"; e0.has(o2);");
/*fuzzSeed-209835301*/count=1246; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - mathy0(mathy2(mathy1(0x100000001, (((( ~ Math.atan2(x, y)) | 0) >= ((( ~ (0x080000000 | 0)) | 0) | 0)) | 0)), (mathy1((y | 0), (((y >>> 0) == (Math.min((y >>> 0), (y >>> 0)) >>> 0)) | 0)) | 0)), (Math.abs((y | 0)) | 0))); }); testMathyFunction(mathy3, [-0x100000001, Number.MIN_SAFE_INTEGER, 0/0, -(2**53-2), 0x100000000, -0x080000001, 2**53-2, Number.MIN_VALUE, 1/0, 0x080000001, -0x0ffffffff, -0x07fffffff, 42, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, 1.7976931348623157e308, -0, 1, Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 0, 0x080000000, 2**53, -(2**53+2), 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-209835301*/count=1247; tryItOut("\"use strict\"; print([,,z1]);function c(/[^]?[^]/yim, eval) { yield 29 } /*ODP-1*/Object.defineProperty(this.e2, \"x\", ({configurable: (x % 4 != 1)}));");
/*fuzzSeed-209835301*/count=1248; tryItOut("mathy1 = (function(x, y) { return Math.sign((( - ( + Math.acosh(Math.sign(Math.fround(Math.asinh(Math.fround(y))))))) ? (( + (( ! Math.fround(mathy0(x, Math.fround((x >= -0x07fffffff))))) < Math.fround(Math.max(-(2**53+2), Math.fround(x))))) >>> 0) : Math.atanh((Math.pow(( + y), ( + y)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[ '' .\u000cthrow(/([^])+/m), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){},  '' .\u000cthrow(/([^])+/m),  '' .\u000cthrow(/([^])+/m), function(){}, function(){},  '' .\u000cthrow(/([^])+/m), function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-209835301*/count=1249; tryItOut("mathy3 = (function(x, y) { return Math.abs(Math.fround(Math.atan2((( ! (( + Math.fround(Math.min(-0x080000001, mathy2(x, x)))) || ( + Math.sqrt(Math.fround(( + Math.fround(x))))))) >>> 0), Math.fround((Math.fround(((x % (( ! Math.hypot(x, x)) | 0)) | 0)) + Math.fround(y)))))); }); testMathyFunction(mathy3, /*MARR*/[ '' , new Boolean(true), new Boolean(true), (0/0), (0/0),  '' ,  '' ,  '' ,  '' , new Boolean(true), (0/0), [undefined],  '' ,  '' , [undefined], [undefined], [undefined], (0/0), new Boolean(true),  '' , (0/0), new Boolean(true),  '' , new Boolean(true),  '' ,  '' , new Boolean(true), (0/0), [undefined], (0/0), [undefined], [undefined], new Boolean(true), (0/0), [undefined], [undefined], new Boolean(true), (0/0), (0/0), (0/0), new Boolean(true), new Boolean(true), [undefined], new Boolean(true),  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , (0/0),  '' , new Boolean(true), (0/0), (0/0), (0/0), (0/0), new Boolean(true),  '' ,  '' , new Boolean(true), [undefined], [undefined], (0/0), [undefined], (0/0),  '' , (0/0), [undefined],  '' , new Boolean(true)]); ");
/*fuzzSeed-209835301*/count=1250; tryItOut("for(let b in ((function  NaN (this.window) '' )(11\n))){; }\nvar peqvyx = new SharedArrayBuffer(8); var peqvyx_0 = new Float32Array(peqvyx); var v0 = g1.runOffThreadScript();c;Array.prototype.sort.call(this.o2.g0.a2, (function() { g2.o2.s1 += 'x'; return this.a2; }), (4277), i0);\n");
/*fuzzSeed-209835301*/count=1251; tryItOut("for (var v of e0) { try { e0 = a1[8]; } catch(e0) { } try { s1 = a0.join(); } catch(e1) { } try { e0.add(e2); } catch(e2) { } i0.valueOf = f2; }");
/*fuzzSeed-209835301*/count=1252; tryItOut("t0[18] = g2.g2;");
/*fuzzSeed-209835301*/count=1253; tryItOut("\"use strict\"; v2 = evalcx(\"b2 = g2.objectEmulatingUndefined();\", g1);");
/*fuzzSeed-209835301*/count=1254; tryItOut("v2 = evalcx(\" /* Comment */ \\\"\\\" .watch(\\\"keys\\\", {} = undefined.watch(\\\"sort\\\", Float64Array).anchor)\", g0);");
/*fuzzSeed-209835301*/count=1255; tryItOut("h1.has = f1;");
/*fuzzSeed-209835301*/count=1256; tryItOut("/*MXX1*/o2 = this.g2.SimpleObject;");
/*fuzzSeed-209835301*/count=1257; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.log(( + (( + ( + ( ! ( ! x)))) >= ( + (((x | 0) >= y) | 0)))))); }); ");
/*fuzzSeed-209835301*/count=1258; tryItOut("var x = (void version(185));a1.unshift(m0, g1.g1.f2, this.g0.f2);");
/*fuzzSeed-209835301*/count=1259; tryItOut("\"use strict\"; neuter(b2, \"same-data\");");
/*fuzzSeed-209835301*/count=1260; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i0);\n    i2 = (!(i1));\n    return +((((1099511627776.0)) - ((((((((0xfc03b914)) ^ ((0xecdd2fe9))) < (((0xf94e7998)) << ((0xa3ce2ea9)))) ? (+(0x641de7a4)) : (((-1.5474250491067253e+26)) - ((1.888946593147858e+22))))) / ((2049.0))))));\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [2**53+2, 0/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, -0, 0x080000001, 0x100000000, 0x07fffffff, 2**53-2, 0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 1, 2**53, -0x07fffffff, -Number.MAX_VALUE, Math.PI, -0x0ffffffff, -0x100000001, -(2**53+2), 0.000000000000001, -0x080000001, 1.7976931348623157e308, 42, -(2**53), -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1261; tryItOut("function(q) { return q; }.prototype;");
/*fuzzSeed-209835301*/count=1262; tryItOut("g1.t0[6] = (x -= NaN);");
/*fuzzSeed-209835301*/count=1263; tryItOut("\"use strict\"; a0 = arguments;");
/*fuzzSeed-209835301*/count=1264; tryItOut("mathy4 = (function(x, y) { return (Math.asinh((Math.fround((Math.fround(Math.acosh((Math.log2(Math.hypot(Math.fround(y), (x <= y))) >>> x))) ? Math.acos(x) : Math.fround((Math.fround((( ~ Math.fround(( - Math.fround(1/0)))) | 0)) && Math.fround(( ~ Math.fround(y))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 0x100000000, 0x07fffffff, -0x07fffffff, 0x080000001, -0, 1.7976931348623157e308, Number.MIN_VALUE, 2**53+2, 0x100000001, 42, 0x0ffffffff, Math.PI, -1/0, 2**53, -(2**53), 0, -(2**53+2), 2**53-2, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=1265; tryItOut("/*RXUB*/var r = r2; var s = {} = arguments; print(s.replace(r, new Function, \"yi\")); ");
/*fuzzSeed-209835301*/count=1266; tryItOut("t2.set(t0, 14);");
/*fuzzSeed-209835301*/count=1267; tryItOut("o1.p1 + t2\n");
/*fuzzSeed-209835301*/count=1268; tryItOut("");
/*fuzzSeed-209835301*/count=1269; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-(2**53+2), 1.7976931348623157e308, 0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, -1/0, -(2**53-2), -0x07fffffff, -0x100000000, 42, -0x100000001, 0/0, 0x100000000, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, -0, 0, -Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, 1, Number.MIN_VALUE, Math.PI, 1/0, -0x0ffffffff, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1270; tryItOut("o1.g2.__proto__ = i0;");
/*fuzzSeed-209835301*/count=1271; tryItOut("o0.toString = (function mcc_() { var eiinio = 0; return function() { ++eiinio; if (/*ICCD*/eiinio % 6 == 3) { dumpln('hit!'); try { v0 = t2.length; } catch(e0) { } try { m0.set(this.b0, v0); } catch(e1) { } try { Array.prototype.splice.apply(a0, [NaN, 19]); } catch(e2) { } o2.m0.set(h0, x); } else { dumpln('miss!'); try { v1 = Object.prototype.isPrototypeOf.call(b1, o2); } catch(e0) { } try { ; } catch(e1) { } for (var v of a1) { try { for (var p in g1) { try { t2[]; } catch(e0) { } try { b2.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { var r0 = x - 6; var r1 = a2 & a8; var r2 = a4 - r1; var r3 = 6 & a1; return a4; }); } catch(e1) { } m2.has(g0.g0); } } catch(e0) { } g1.v0 = undefined; } } };})();");
/*fuzzSeed-209835301*/count=1272; tryItOut("\"use strict\"; for (var v of a1) { try { this.v2 = Object.prototype.isPrototypeOf.call(o0, i1); } catch(e0) { } Array.prototype.unshift.apply(o0.a0, [v0, p0]); }\nswitch(x) { default: (/[^]/i);case 4:  }\n");
/*fuzzSeed-209835301*/count=1273; tryItOut("\"use strict\"; v1.__proto__ = p1;");
/*fuzzSeed-209835301*/count=1274; tryItOut("e1.add(p1);");
/*fuzzSeed-209835301*/count=1275; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atanh(Math.fround((Math.max(Math.hypot((Math.imul((-Number.MIN_SAFE_INTEGER ? ((y >>> 0) !== ( + Math.pow(Number.MAX_VALUE, y))) : ((Math.clz32((y >>> 0)) <= (x >>> 0)) >>> 0)), x) | 0), ( + mathy1((y | 0), (y | 0)))), (( + Math.log(( + (( + x) && (x != y))))) | 0)) | 0))); }); ");
/*fuzzSeed-209835301*/count=1276; tryItOut("\"use strict\"; \"use asm\"; const v0 = t2.BYTES_PER_ELEMENT;/*MXX2*/g2.Int16Array.BYTES_PER_ELEMENT = m2;");
/*fuzzSeed-209835301*/count=1277; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, 1.7976931348623157e308, 42, 0x080000000, -(2**53-2), 2**53+2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, -0x080000000, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, 0, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, 2**53-2, 0.000000000000001, -0x07fffffff, -(2**53+2), -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 1, -Number.MAX_VALUE, -0x100000001, -0x0ffffffff, Math.PI, 0x0ffffffff, 1/0, -1/0]); ");
/*fuzzSeed-209835301*/count=1278; tryItOut("mathy1 = (function(x, y) { return (((Math.log(((( + (Math.atan2(((Math.ceil((Math.asin(x) >>> 0)) >>> 0) >>> 0), ( + x)) >>> 0)) && (( + (( + ((((Math.pow(x, ( + y)) != y) >>> 0) >> (y >>> 0)) >>> 0)) & ( + (x - (( ! y) >>> 0))))) >>> 0)) >>> 0)) >>> 0) === (( + ( - ( + Math.max(((y ? ( ! ( + x)) : Math.hypot(0x07fffffff, x)) << x), -(2**53))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 2**53, -0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, 1.7976931348623157e308, -(2**53), -0x080000001, 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 0/0, -(2**53+2), Math.PI, 0, 0x080000000, -1/0, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, -Number.MIN_VALUE, -0x080000000, -0x100000000, 0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, 42, 2**53-2, 0.000000000000001, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1279; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((((( ! ( + ( - ( + ((Math.sin((y | 0)) | 0) < y))))) < ( + (Math.atan2(y, (Math.pow((y | 0), (((y >>> 0) | x) >>> 0)) | 0)) >> (mathy0((Math.round(Math.atan2(x, (-0x100000001 >>> 0))) >>> 0), (x | 0)) >>> 0)))) >>> 0) | 0) + ((Math.fround((Math.ceil(y) | 0)) * ((( - (( + mathy0(( + (x >= x)), Math.round(y))) >>> 0)) >>> 0) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy2, [0x100000000, -1/0, 42, -0x080000000, -(2**53+2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, 1/0, -0x100000000, 2**53, 0x080000001, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 2**53-2, -(2**53), 2**53+2, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, -0, Math.PI, 0, -0x100000001, Number.MIN_VALUE, -0x080000001, 0/0]); ");
/*fuzzSeed-209835301*/count=1280; tryItOut("\"use strict\"; if(new x([1], [])) {v0 + ''; }");
/*fuzzSeed-209835301*/count=1281; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=1282; tryItOut("/*RXUB*/var r = r1; var s = s2; print(s.replace(r, x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: Object.defineProperties, fix: Array.prototype.splice, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(allocationMarker()), (1 for (x in [])), q => q))); ");
/*fuzzSeed-209835301*/count=1283; tryItOut("switch(([] = (URIError((q => q).call(\u3056, ))) === \"\\u8345\")) { case Uint32Array(): break;  }");
/*fuzzSeed-209835301*/count=1284; tryItOut("/*RXUB*/var r = /(?!(?:[^]+){0,3}[\\cE\\u0093-\\u1D61\uacd2\\W]|(?:\\d?){2,6})^|($|^?|(?=[^]{2097151}){1,})|(?:\\2)|\\d{1,}/gym; var s = new ((encodeURI).call)(); print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=1285; tryItOut("");
/*fuzzSeed-209835301*/count=1286; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1287; tryItOut("\"use strict\"; i1.send(i2);");
/*fuzzSeed-209835301*/count=1288; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return (Math.expm1(( + mathy0(( + ((((Math.sign(x) | 0) | 0) | Math.asinh(x)) | 0)), ( + 0x0ffffffff)))) > ((( + Math.imul((Math.atan2(x, ((Math.fround(y) == Math.imul(0.000000000000001, (x | 0))) | 0)) >>> 0), (( + Math.fround((Math.fround(-0x100000000) % Math.fround(x)))) >>> 0))) == (x ^ (((( ~ Number.MAX_VALUE) << y) >> (x ? mathy1(y, x) : x)) | 0))) | 0)); }); testMathyFunction(mathy2, [null, NaN, 1, 0.1, (new Boolean(true)), ({valueOf:function(){return '0';}}), '\\0', ({valueOf:function(){return 0;}}), -0, '0', [], (new Boolean(false)), undefined, (new Number(-0)), objectEmulatingUndefined(), [0], /0/, true, false, (function(){return 0;}), '/0/', ({toString:function(){return '0';}}), '', (new String('')), 0, (new Number(0))]); ");
/*fuzzSeed-209835301*/count=1289; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (Math.sqrt(Math.max(-Number.MAX_SAFE_INTEGER, ( ~ (-0x100000000 - y)))) | 0)) | 0); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0x080000001, -1/0, 1/0, 2**53-2, 0, 0/0, Math.PI, -0x080000000, -Number.MAX_VALUE, 0x07fffffff, 2**53+2, 0x100000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 2**53, -0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 42, Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, 0x100000000, -0x080000001, -0x100000000, 0.000000000000001, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1290; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.sinh((Math.atan2(((Math.acos(x) && Math.min(Math.imul(y, Math.min((y | 0), (x >>> 0))), 0x080000001)) >>> 0), (Math.pow((Math.atan2(Math.fround(Math.hypot(y, x)), y) | 0), Number.MAX_VALUE) | 0)) >>> 0)) | 0), Math.acos(( + ( - ( + Math.atan2(Math.fround((Math.max((x >>> 0), (y >>> 0)) >>> 0)), ( + x))))))) | 0); }); ");
/*fuzzSeed-209835301*/count=1291; tryItOut("\"use strict\"; s0 = '';");
/*fuzzSeed-209835301*/count=1292; tryItOut("\"use strict\"; s0 += o1.s1;");
/*fuzzSeed-209835301*/count=1293; tryItOut("\"use strict\"; { void 0; bailAfter(533); }");
/*fuzzSeed-209835301*/count=1294; tryItOut("a1.reverse(p0);");
/*fuzzSeed-209835301*/count=1295; tryItOut("a1.forEach((function() { try { v2 = (s0 instanceof this.g0.p1); } catch(e0) { } try { o0.a0[({valueOf: function() { print(uneval(p0));function x(x) { o2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((((Uint8ArrayView[2]))>>>((i1)+(0x5eade120)-(0xf95c4593))) / ((timeout(1800)))))|0;\n  }\n  return f; })(this, {ff: null}, new ArrayBuffer(4096)); } print(x);\nArray.prototype.push.apply(a0, [o0, h0,  /x/g , o1]);\nreturn 2; }})] =  '' ; } catch(e1) { } try { v0 = (g0.t2 instanceof g0.p0); } catch(e2) { } s1 = ''; return o1; }));");
/*fuzzSeed-209835301*/count=1296; tryItOut("Array.prototype.sort.apply(o0.g1.a1, [(function() { e0.has((Math.pow(new RegExp(\"(?![^]|\\\\w)|((?!\\\\d))|\\\\x96|.*?|$|[\\\\W\\\\d\\\\W]+?|(\\\\n){1}(?=.)*?|\\\\W|[\\u00fd\\\\S\\uba10\\\\W]\", \"m\"), (eval(\"[,,]\", b)).__defineSetter__(\"x\", Object.getOwnPropertyDescriptors)))); return i1; }), h1]);");
/*fuzzSeed-209835301*/count=1297; tryItOut("\"use strict\"; var yxqrso, [] = /*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q')].map, y = ({} = \"\\u808F\");/*MXX1*/o1 = g2.String.prototype.length;");
/*fuzzSeed-209835301*/count=1298; tryItOut("a0 = r1.exec(s2);");
/*fuzzSeed-209835301*/count=1299; tryItOut("let (z) { /* no regression tests found */\na0.reverse()\n }Object.defineProperty(this, \"s2\", { configurable: false, enumerable: (( + (((Math.pow((((( - x) | 0) > ( + Math.log1p(Math.atan2(x, 0x07fffffff)))) | 0), Math.fround((Math.fround((( + Math.pow(( + Math.tan(x)), ( + Math.fround(Math.min(x, (Math.sinh(Math.fround(x)) | 0)))))) >>> Math.acosh(function() { return this; }))) ^ Math.fround(Math.fround((Math.fround(Math.min(Math.min(x, x), x)) & Math.log1p(Math.fround(x)))))))) >>> 0) >>> (( + ((((( + ( + (Math.acosh(x) << ( ~ x)))) < Math.atan(( - (( + x) / ( + x))))) | 0) > (Math.tanh(( + ( ! ( + x)))) >>> 0)) | 0)) >>> 0)) >>> 0))),  get: function() {  return ''; } });");
/*fuzzSeed-209835301*/count=1300; tryItOut("\"use strict\"; v0.toSource = this.f0;");
/*fuzzSeed-209835301*/count=1301; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - (Math.imul((Math.atan(( ~ -0x07fffffff)) >>> 0), (( ~ y) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, -(2**53-2), Math.PI, 2**53+2, -(2**53+2), 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 2**53-2, 2**53, 0x100000000, -0x100000000, -0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0x100000001, 0.000000000000001, 0/0, -0x080000000, 1, Number.MAX_VALUE, -0x0ffffffff, -0, 0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, -1/0, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), 42]); ");
/*fuzzSeed-209835301*/count=1302; tryItOut("\"use strict\"; b0 = t1.buffer;((4277));");
/*fuzzSeed-209835301*/count=1303; tryItOut("\"use strict\"; g1.o2.toString = (function() { try { Array.prototype.pop.apply(a2, []); } catch(e0) { } try { neuter(b0, \"change-data\"); } catch(e1) { } try { t0[17] = /((?=(?=[\\xd1\\d\\W])){1}(${2,8388610}|\u00fa)){1}{3,6}/gm; } catch(e2) { } o0.s2 = t2[(e %= z) ? -28 : (4277)]; return g0; });");
/*fuzzSeed-209835301*/count=1304; tryItOut("mathy2 = (function(x, y) { return (Math.imul(( ~ Math.sign((Math.trunc(y) | 0))), (Math.imul(Math.fround(mathy0(Math.cos(y), ( + Math.atan2(( + (( + (Math.fround(x) < Math.fround(Math.pow(0x100000001, Number.MIN_SAFE_INTEGER)))) === Math.fround(x))), Math.fround((y ? x : 2**53-2)))))), ( ~ (((Math.hypot(( ~ -0x080000001), x) >>> 0) | (Math.sqrt(x) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[function(){}, function(){}, (1/0), function(){}, function(){}, function(){}, function(){}, (1/0), function(){}, (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (1/0), function(){}, (1/0), (1/0), function(){}, (1/0), (1/0), function(){}, function(){}, function(){}, function(){}, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), function(){}, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), function(){}, (1/0), function(){}, (1/0), (1/0), (1/0), (1/0), (1/0), function(){}, (1/0), function(){}, function(){}, function(){}, (1/0), (1/0), (1/0), function(){}, function(){}, function(){}, (1/0), (1/0), (1/0), function(){}, (1/0), function(){}, (1/0), function(){}, function(){}, (1/0), (1/0), (1/0), function(){}, function(){}, (1/0), (1/0), function(){}, (1/0), function(){}, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, (1/0), (1/0), (1/0), (1/0), function(){}, function(){}, (1/0), function(){}, (1/0), (1/0), function(){}, function(){}, (1/0), function(){}, (1/0), (1/0), function(){}, function(){}, function(){}, (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, (1/0), (1/0), (1/0)]); ");
/*fuzzSeed-209835301*/count=1305; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( - ( + ( ~ ( + (0x0ffffffff !== ( ~ ( + Math.max(( + Math.trunc(y)), (x >>> 0))))))))) >>> 0); }); ");
/*fuzzSeed-209835301*/count=1306; tryItOut("((4277));");
/*fuzzSeed-209835301*/count=1307; tryItOut("(a);");
/*fuzzSeed-209835301*/count=1308; tryItOut("a0.pop();");
/*fuzzSeed-209835301*/count=1309; tryItOut("o1.g1 + p0;");
/*fuzzSeed-209835301*/count=1310; tryItOut("v0 = a1.length;");
/*fuzzSeed-209835301*/count=1311; tryItOut("g0.g0.offThreadCompileScript(\"print(x);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 74 == 38), noScriptRval: (x % 22 == 4), sourceIsLazy:  /x/ , catchTermination: true }));s1 = '';");
/*fuzzSeed-209835301*/count=1312; tryItOut("var imereo = new ArrayBuffer(2); var imereo_0 = new Uint32Array(imereo); print(imereo_0[0]); var imereo_1 = new Uint32Array(imereo); var imereo_2 = new Float32Array(imereo); var imereo_3 = new Float32Array(imereo); imereo_3[0] = -23; var imereo_4 = new Int32Array(imereo); print(imereo_4[0]); imereo_4[0] = -1707207496; var imereo_5 = new Uint8Array(imereo); print(imereo_5[0]); imereo_5[0] = 0; var imereo_6 = new Float64Array(imereo); print(imereo_6[0]); imereo_6[0] = 20; var imereo_7 = new Int32Array(imereo); print(imereo_7[0]); imereo_7[0] = -16; var imereo_8 = new Int32Array(imereo); imereo_8[0] = 10; var imereo_9 = new Uint8Array(imereo); Array.prototype.unshift.apply(o1.a2, [p0, e2, this.m1, imereo_8[8], b1, o0, Math.cosh((4277))]);with((yield  /x/ ))return;print(imereo_6);/*ADP-3*/Object.defineProperty(a1, ({valueOf: function() { /*RXUB*/var r = /(?:(?:\\b|\\D(?:\\b+?))?)/gym; var s = \"_\\u0086\"; print(r.test(s)); return 10; }}), { configurable: (imereo_7 % 5 == 4), enumerable: false, writable: ({/*TOODEEP*/})( /x/g ).throw(imereo_0[10] = null)/*\n*/, value: o0.a0 });for(var [b, d] = ((uneval( /x/ ))) in \"\\uDE2B\") {e2 = new Set(s2);M:for(let [x, c] = undefined in  \"\" ) v1 = (h2 instanceof g2); }");
/*fuzzSeed-209835301*/count=1313; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a1, [this.p2, v0]);");
/*fuzzSeed-209835301*/count=1314; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.atanh(Math.fround(((Math.fround(Math.fround(((Math.log2(x) >>> 0) & Math.fround(y)))) | ( + Math.hypot(((( + Math.clz32(( + ( ~ y)))) < Math.min(-1/0, x)) | 0), ((-(2**53+2) & Math.hypot(y, ((((( ! (Math.PI >>> 0)) >>> 0) >>> 0) << (x >>> 0)) >>> 0))) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, 0/0, 42, -0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0x100000000, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, -0, -(2**53-2), -(2**53+2), -Number.MIN_VALUE, 2**53+2, 2**53-2, -(2**53), -0x100000000, 1/0, -0x080000001, 0x0ffffffff, -0x100000001, 2**53, 0, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1315; tryItOut("try { (intern(\"\\u38D2\")); } catch(x) { with({}) x.message; } with({}) for(let x in /*MARR*/[null, new Boolean(false), new Boolean(false)]) for(let a of /*MARR*/[function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}]) NaN = a;");
/*fuzzSeed-209835301*/count=1316; tryItOut("mathy3 = (function(x, y) { return (Math.cbrt((( - Math.atanh(Math.fround(((Math.fround(mathy0(x, x)) >>> -Number.MAX_VALUE) - (( + x) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 1/0, -0x080000000, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -0x080000001, 42, 0x07fffffff, 1, -0x100000001, Number.MAX_SAFE_INTEGER, 0, -(2**53+2), 0x100000000, -0x100000000, 0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, 0x0ffffffff, -0x0ffffffff, 2**53-2, Math.PI, 0x080000001, 1.7976931348623157e308, 2**53, -Number.MIN_VALUE, -(2**53-2), Number.MIN_VALUE, -(2**53), 2**53+2]); ");
/*fuzzSeed-209835301*/count=1317; tryItOut("\"use strict\"; m0.has(i2);");
/*fuzzSeed-209835301*/count=1318; tryItOut("\"use strict\"; for (var p in v0) { try { g2.b1 + ''; } catch(e0) { } /*RXUB*/var r = g2.r2; var s = \"\\u0cae\\n\\n\\uecf3\\u954c\\n\\n\\n\\u2438\\n\\n\"; print(uneval(r.exec(s)));  }");
/*fuzzSeed-209835301*/count=1319; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.fround(( ~ (Math.expm1((( ~ (Math.fround((y >>> 0)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, -0x080000000, 1/0, 0x100000000, -0x080000001, -(2**53-2), -0, -0x100000001, 0x080000000, -(2**53), 0x080000001, 2**53, -(2**53+2), 0.000000000000001, 0x100000001, 1, 0, -1/0, 42, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-209835301*/count=1320; tryItOut("\"use strict\"; ([] = x);");
/*fuzzSeed-209835301*/count=1321; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0((( - x) || (((((x + (0x080000000 | 0)) | 0) | 0) ? (x | 0) : (Math.cbrt((Math.trunc(x) | 0)) | 0)) | 0)), Math.log2(Math.fround(Math.atan2(Math.fround(Math.trunc((( ~ ((42 ? x : 0x080000000) >>> 0)) >>> 0))), x)))) | 0); }); ");
/*fuzzSeed-209835301*/count=1322; tryItOut("m0.has(m0);");
/*fuzzSeed-209835301*/count=1323; tryItOut("\"use strict\"; g0.v0 = (i0 instanceof o2.m1);");
/*fuzzSeed-209835301*/count=1324; tryItOut("\"use strict\"; M:if(/*MARR*/[{}, function(){}, {},  /x/ ,  /x/ , {}, (-1/0), function(){}, {}, (void 0), {},  /x/ , (void 0), {}, function(){},  /x/ , {}, (void 0), (-1/0), (void 0), (void 0), function(){}, (void 0), (void 0), (-1/0), function(){}, {},  /x/ , function(){}, (-1/0),  /x/ , (-1/0), function(){}, (-1/0), (void 0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/ , (-1/0), {},  /x/ , (-1/0), (void 0), (-1/0), (-1/0), function(){}, function(){}, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0),  /x/ , (-1/0), {}, (-1/0), function(){}, {}, (void 0),  /x/ , {},  /x/ , (void 0),  /x/ , {}, (void 0), {},  /x/ ,  /x/ , {}, (-1/0), (-1/0), {}, (-1/0), {},  /x/ , {}, (-1/0), (-1/0),  /x/ ,  /x/ , {}, function(){},  /x/ , function(){},  /x/ ,  /x/ , (-1/0), (-1/0), (void 0), function(){},  /x/ , {}, (-1/0), {}, function(){},  /x/ , (-1/0), (void 0), function(){}, function(){}, function(){}, {}, (-1/0), function(){}, (void 0), (void 0), {}, function(){},  /x/ , (void 0), (void 0), (-1/0), function(){}, (void 0),  /x/ , {}, {}, {}, {}, function(){},  /x/ , (void 0), {},  /x/ , (-1/0)].some(function (z, b) { t0 = new Int8Array(({valueOf: function() { g2.valueOf = (function() { Object.defineProperty(this, \"v1\", { configurable: [z1,,], enumerable: (x % 31 == 20),  get: function() {  return false; } }); return a1; });return 5; }})); } , ([new RegExp(\"\\\\B|[^][^](?:(?=\\\\u33d5)*\\\\1)\\\\3*?|[\\\\\\u00a1-\\u8479\\\\x58][][\\\\W]{4}?\", \"gym\")]))) { if (x) {o1.v0 = (a2 instanceof f1); } else const d = /\\s/gm;for (var v of g2.g0) { try { f2.toString = (function() { g0.a1.splice(h0); return this.m1; }); } catch(e0) { } print(b1); }}");
/*fuzzSeed-209835301*/count=1325; tryItOut("m2.delete(e0);");
/*fuzzSeed-209835301*/count=1326; tryItOut("\"use strict\"; i0 = new Iterator(t1);");
/*fuzzSeed-209835301*/count=1327; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=1328; tryItOut("function  x (x) { this.b0 = a2[14]; } .throw( /x/ );");
/*fuzzSeed-209835301*/count=1329; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy2, [1.7976931348623157e308, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, -0x0ffffffff, 2**53, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 0, 0.000000000000001, 0/0, -0x07fffffff, 42, Number.MIN_VALUE, Math.PI, -(2**53), -0x080000000, 0x100000000, -0x080000001, -0x100000001, 0x080000000, 0x0ffffffff, 1, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, 2**53+2, 0x080000001]); ");
/*fuzzSeed-209835301*/count=1330; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.abs(( + Math.asin((x <= mathy0((y <= (x | 0)), (Math.atan2(y, ( + (( ~ (x | 0)) | 0))) | 0)))))); }); testMathyFunction(mathy1, [0.000000000000001, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, 0/0, -(2**53), Math.PI, 42, 2**53+2, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 1.7976931348623157e308, -0, 0x080000001, Number.MIN_VALUE, -0x100000001, -0x100000000, Number.MAX_VALUE, 0x100000000, -(2**53-2), -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, 1, -1/0, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1331; tryItOut("\"use strict\"; e2 + '';");
/*fuzzSeed-209835301*/count=1332; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (mathy1(((( + ( - (mathy1((( + Math.fround(Math.tanh(Math.fround(Math.min(-(2**53), x))))) | 0), Math.fround(Math.fround((Math.fround(0) && y)))) | 0))) >>> 0) | 0), (Math.fround(Math.pow((( + (Math.sinh(y) | 0)) - (Math.max(( + (Math.fround(y) ? Math.fround(Math.asin((y | 0))) : Math.fround(0x080000001))), 0x080000001) | 0)), ((x != ((( + (y | 0)) | 0) >>> 0)) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-209835301*/count=1333; tryItOut("\"use strict\"; h1.getPropertyDescriptor = (function(j) { f1(j); });");
/*fuzzSeed-209835301*/count=1334; tryItOut("/*RXUB*/var r = /\\b/; var s = \"a1~\\ud9e0 a\\n +\\n\\u00ed\\n\\u009d\"; print(s.replace(r, '\\u0341')); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=1335; tryItOut("/*RXUB*/var r = /(\\b{1})|\\1|^*/g; var s = \"111111\"; print(s.replace(r, function(y) { return (void options('strict_mode')) })); function c()\"\\u3458\"i1.next();");
/*fuzzSeed-209835301*/count=1336; tryItOut("v1 = a0.reduce, reduceRight(e1, o2);");
/*fuzzSeed-209835301*/count=1337; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.fround(Math.fround(( + Math.fround(Math.hypot(((( ~ ( + y)) | 0) >>> 0), (-0x080000000 & ( + Math.round(Math.fround(mathy3(x, -1/0)))))))))), Math.fround(Math.ceil((mathy0(Math.fround((Math.fround(( + Math.fround(y))) & Math.fround(((( ! (x | 0)) | 0) + x)))), (Math.atanh(Math.log1p(y)) | 0)) >>> 0))))); }); testMathyFunction(mathy5, [-0x080000001, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 0.000000000000001, -0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 1, 0, -Number.MAX_VALUE, -1/0, 0x0ffffffff, 2**53+2, Number.MIN_VALUE, -(2**53-2), 2**53, 2**53-2, 0x080000001, 1.7976931348623157e308, Math.PI, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 0/0, Number.MAX_VALUE, -(2**53+2), -0x080000000, -0x100000001, 42]); ");
/*fuzzSeed-209835301*/count=1338; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-209835301*/count=1339; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( - ((( + Math.min((x >>> 0), (0x100000000 | 0))) - ( + (Math.imul(((Math.fround(Math.atan2(( + Math.abs(x)), x)) <= (((x >>> 0) % (x >>> 0)) >>> 0)) >>> 0), (x >>> 0)) >>> 0))) % ( + ( + Math.fround(( ~ (y | 0))))))); }); testMathyFunction(mathy5, [-0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0x0ffffffff, -1/0, 0x100000001, 1.7976931348623157e308, -(2**53+2), 1/0, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, 0x080000000, 42, 2**53-2, Number.MIN_VALUE, 1, 2**53+2, 0.000000000000001, -0x100000000, 0x100000000, 0/0, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, 0, -0, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-209835301*/count=1340; tryItOut("\"use strict\"; v2 = g0.runOffThreadScript();");
/*fuzzSeed-209835301*/count=1341; tryItOut("/*iii*/if(function(id) { return id }) ( /x/ );var e = (Math.pow(srbfgq, 2));/*hhh*/function srbfgq(){print(x);function x(x = -25, c) { \"use strict\"; return \"\\uD4E9\" } /*RXUB*/var r = r0; var s = \"aaaaaaaaaaaa\"; print(r.test(s)); print(r.lastIndex); }");
/*fuzzSeed-209835301*/count=1342; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ (( ~ Math.fround(Math.max(((x % Math.expm1(( - x))) >>> 0), (Math.imul(Math.fround(y), Math.fround((( ! x) | 0))) >>> 0)))) | 0)); }); testMathyFunction(mathy0, [2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000000, 42, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 0x100000000, Math.PI, -(2**53-2), 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -0, -0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, Number.MAX_VALUE, -0x080000001, 2**53, -1/0, 1/0, -0x080000000, 1.7976931348623157e308, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, 1, 0x07fffffff, -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-209835301*/count=1343; tryItOut("g1.offThreadCompileScript(\"a0.unshift(this.p2, t0);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: (x % 13 != 9), sourceIsLazy: (x % 3 == 2), catchTermination: false }));");
/*fuzzSeed-209835301*/count=1344; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.hypot((((x ? Math.atan2(x, y) : x) >>> 0) - x), ((mathy0((y >>> 0), ( + Math.asinh(( ~ 42)))) >>> 0) >= Math.min(x, x)))) , Math.fround(Math.cbrt(Math.min(Number.MIN_VALUE, ( ! (( + ( + ((2**53+2 | 0) < ( + x)))) >>> 0))))))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, 42, 0x080000001, -0x07fffffff, Number.MIN_VALUE, -1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, -0x080000001, -0x0ffffffff, 0, 0x0ffffffff, 1, 0/0, 0x080000000, 0.000000000000001, Math.PI, 0x100000000, 2**53-2, -(2**53-2), -0x080000000, 2**53, -0, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-209835301*/count=1345; tryItOut("a2 = arguments.callee.arguments;");
/*fuzzSeed-209835301*/count=1346; tryItOut("t2 = t0.subarray(({valueOf: function() { {/*RXUB*/var r = new RegExp(\"^\\\\B+?(((?:$+)))\\\\3($)^*|\\\\1|(?:\\\\b)${4}{3,}\", \"yi\"); var s = \"\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u2010\\n\\n\\n\\n\\n\\u0cae\\n\\n\\uecf3\\u954c\\n\\n\\n\\u2438\\n\\n1\\n1\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u524f\\n\\n\\n\\u0cae\\n\\n\\uecf3\\u954c\\n\\n\\n\\u2438\\n\\n1\\n1\\n\\n\\u524f\\n\\u524f\\n\\u524f\\n\\n\\n\\n\\n\\u0cae\\n\\n\\uecf3\\u954c\\n\\n\\n\\u2438\\n\\n1\\n1\\n\\u0cae\\n\\n\\uecf3\\u954c\\n\\n\\n\\u2438\\n\\n1\\n1\\n\\u0cae\\n\\n\\uecf3\\u954c\\n\\n\\n\\u2438\\n\\n1\\n1\\n\"; print(uneval(s.match(r)));  }return 7; }}), x|=\"\\uE04F\" & x &= x);");
/*fuzzSeed-209835301*/count=1347; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=1348; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - (Math.clz32(( + 1/0)) ** mathy4(Math.fround(Math.atan2(y, ( + Math.atan2(Math.fround((( ! Math.fround(y)) >>> 0)), Math.fround(( + (( + Math.asin(y)) != ( + x)))))))), ((x >>> 0) || Math.imul((Math.min(y, -(2**53+2)) >>> x), x))))) | 0); }); testMathyFunction(mathy5, [42, Math.PI, 2**53-2, 0x0ffffffff, -0x080000001, Number.MAX_VALUE, 1, -1/0, -Number.MAX_VALUE, -0x100000000, 0, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 1/0, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, -Number.MIN_VALUE, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -(2**53), Number.MIN_VALUE, 0/0, -0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1349; tryItOut("\"use strict\"; print( /x/g .throw(window) , new RegExp(\"(\\\\W){3,}\", \"m\"));");
/*fuzzSeed-209835301*/count=1350; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.cbrt(Math.exp(Math.min(Math.fround(Math.log(y)), ( ! Math.fround(((x >>> 0) ? x : ((mathy0(((x << x) >>> 0), (y >>> 0)) >>> 0) >>> 0))))))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53-2), 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 42, 2**53, 1, 0x0ffffffff, 0/0, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0x100000000, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53), -0x080000000, -0x080000001, -0, Math.PI, 2**53+2, Number.MIN_VALUE, -1/0, -0x100000000, -0x0ffffffff, 0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1351; tryItOut("print(a = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(b), (4277)));");
/*fuzzSeed-209835301*/count=1352; tryItOut("Array.prototype.unshift.apply(a1, [t0, g2, p1, new (let (e=eval) e)( '' , (4277))]);");
/*fuzzSeed-209835301*/count=1353; tryItOut("function shapeyConstructor(ovgfsi){for (var ytqzftnvm in this) { }this[\"preventExtensions\"] = true;this[\"preventExtensions\"] =  \"\" ;return this; }\n({});\n");
/*fuzzSeed-209835301*/count=1354; tryItOut("p2.__proto__ = this.e1;");
/*fuzzSeed-209835301*/count=1355; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-209835301*/count=1356; tryItOut("/*hhh*/function gqrnvn(eval, x, ...x){g1 = this;}/*iii*/this.s2 = new String;");
/*fuzzSeed-209835301*/count=1357; tryItOut("");
/*fuzzSeed-209835301*/count=1358; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1359; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, -1/0, -Number.MIN_VALUE, 0/0, 2**53, -Number.MAX_VALUE, 0x07fffffff, -0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -0, 0x100000001, 1, -(2**53), 1.7976931348623157e308, Number.MAX_VALUE, 1/0, 42, Number.MIN_VALUE, -0x100000001, -0x0ffffffff, 0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), 0, 2**53-2, 0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, -0x080000000]); ");
/*fuzzSeed-209835301*/count=1360; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.ceil((Math.log1p((Math.fround(Math.pow(( + (( ! (y | x)) | 0)), Math.min((( ! ((x > y) >>> 0)) >>> 0), 2**53+2))) | 0)) | 0)); }); testMathyFunction(mathy1, [-0, [0], '', '\\0', NaN, ({valueOf:function(){return '0';}}), '/0/', /0/, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), false, (new Number(-0)), undefined, (new Boolean(false)), (new Number(0)), (new Boolean(true)), '0', 0, 1, (function(){return 0;}), [], null, (new String('')), true, objectEmulatingUndefined(), 0.1]); ");
/*fuzzSeed-209835301*/count=1361; tryItOut("testMathyFunction(mathy1, [2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, 42, 0x100000001, -(2**53-2), -0x080000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 0x100000000, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, 0/0, 2**53+2, 0x080000001, -0x100000000, -0, -0x0ffffffff, -1/0, 1/0, -Number.MIN_VALUE, 1, 0, -0x080000000]); ");
/*fuzzSeed-209835301*/count=1362; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( + ( + ((Math.atan2((y >>> 0), ( + ((mathy0(( + ((Math.pow(x, Math.PI) & ((Math.asinh((-(2**53) | 0)) | 0) | 0)) | 0)), (Math.log10(y) >>> 0)) >>> 0) && (x && x)))) | ( + (mathy2((y >>> 0), (Math.log1p(Math.cbrt(Math.tan(x))) >>> 0)) >>> 0))) >>> 0)))); }); ");
/*fuzzSeed-209835301*/count=1363; tryItOut("print(x);");
/*fuzzSeed-209835301*/count=1364; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - Math.pow(Math.imul(Math.max(x, -Number.MAX_SAFE_INTEGER), ( ~ x)), Math.cos(y))); }); testMathyFunction(mathy3, [-(2**53), 0x07fffffff, -0x100000001, 1, -Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 42, 0x080000000, -0x100000000, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, 2**53-2, -(2**53-2), -0x080000000, Number.MAX_VALUE, 0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 2**53, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, -0, Number.MIN_VALUE, 2**53+2, 0/0, -(2**53+2), 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=1365; tryItOut("var ojbwsu = new SharedArrayBuffer(0); var ojbwsu_0 = new Uint8ClampedArray(ojbwsu); ojbwsu_0[0] = 0x07fffffff; e0.add(f0);");
/*fuzzSeed-209835301*/count=1366; tryItOut("\"use strict\"; const w = (eval(\"/* no regression tests found */\", (new (function(x, y) { return -0x100000001; })(!(4277))))).yoyo(({}) = (({x, b: {x: {x: x, w}}} = (x) = /([^]+\\b|.|$*,+?*)/gyi)));/*tLoop*/for (let c of /*MARR*/[new Number(1), function(){}, [], function(){}, function(){}, new Number(1), [], [], new Number(1), [], new Number(1), function(){}, function(){}, function(){}, [], new Number(1), [], [], new Number(1), function(){}, new Number(1), new Number(1), new Number(1), [], [], new Number(1), [], new Number(1), [], [], new Number(1), new Number(1), function(){}]) { throw  /x/g ; }");
/*fuzzSeed-209835301*/count=1367; tryItOut("\"use strict\"; Array.prototype.shift.call(g0.a2, i0, v2, e0, this.o1.v1, e2);");
/*fuzzSeed-209835301*/count=1368; tryItOut("\"use strict\"; xbnkwq, iywusl, 2, z, elbfue, b;v2 = Object.prototype.isPrototypeOf.call(s1, t0);");
/*fuzzSeed-209835301*/count=1369; tryItOut("\"use strict\"; a1[6];");
/*fuzzSeed-209835301*/count=1370; tryItOut("\"use strict\"; \"use asm\"; p1 = t1[10];\no2.e1.delete(v2);\n");
/*fuzzSeed-209835301*/count=1371; tryItOut("mathy5 = (function(x, y) { return Math.hypot(((( + Math.fround(Math.fround((( ! (( + Math.log2((x ? (( - (x >>> 0)) >>> 0) : (x | 0)))) >>> 0)) >>> 0)))) ** ( + mathy4((Math.atan2(Math.fround(x), Math.sqrt(y)) >>> 0), (( + (y | 0)) | 0)))) >>> 0), Math.fround(mathy1(Math.fround(( + (Math.fround(( - (0x080000000 >>> 0))) >>> 0))), ( + ( + (-0x100000000 << ( + Math.fround((( + Math.imul(x, y)) ^ y))))))))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0, 0, Number.MAX_VALUE, -(2**53-2), 0x080000000, Math.PI, -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 0x080000001, 2**53-2, 0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 1, 0x100000001, 1/0, -0x07fffffff, 0/0, 0x100000000, 42, Number.MIN_VALUE, 2**53+2, 0x07fffffff, -0x100000000, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, -1/0, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-209835301*/count=1372; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-209835301*/count=1373; tryItOut("\"use strict\"; function shapeyConstructor(ranulo){\"use strict\"; { with(x)e0 + ''; } for (var ytqvttohq in this) { }delete this[\"parseFloat\"];return this; }/*tLoopC*/for (let a of /*FARR*/[([,])(20) <<= {} = let (x = (function ([y]) { })())  /x/g ]) { try{let leinag = shapeyConstructor(a); print('EETT'); /*MXX1*/o2 = g2.URIError.prototype.constructor;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-209835301*/count=1374; tryItOut("\"use strict\"; e2 + '';");
/*fuzzSeed-209835301*/count=1375; tryItOut("\"use strict\"; print(({y: x}));");
/*fuzzSeed-209835301*/count=1376; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; fullcompartmentchecks(false); } void 0; } /*ODP-3*/Object.defineProperty(h1, \"entries\", { configurable: false, enumerable: false, writable: (x % 4 != 3), value: t1 });m0 + this.t2;");
/*fuzzSeed-209835301*/count=1377; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.asinh(((((( + Math.cos(y)) >>> 0) | Math.fround(Math.atan2((( ! ((Math.pow((Math.fround(Math.hypot(y, y)) >>> 0), x) >>> 0) | 0)) | 0), Math.fround(( ! Math.fround(Math.min(Math.fround(y), ((Math.max((x | 0), (y | 0)) | 0) || Math.PI)))))))) >>> 0) | 0)); }); testMathyFunction(mathy2, [-1/0, -Number.MAX_VALUE, -(2**53-2), 1, 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, 0/0, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, -0x080000001, -(2**53+2), 0, 0x080000001, -0x100000000, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, 2**53+2, 42, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 1.7976931348623157e308]); ");
/*fuzzSeed-209835301*/count=1378; tryItOut("\"use strict\"; this.i0 + '';");
/*fuzzSeed-209835301*/count=1379; tryItOut("testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53-2), 0/0, 0x080000000, 0x0ffffffff, -0x07fffffff, -0x080000001, 0.000000000000001, -0, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0, -0x100000000, 2**53, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53-2, 1, -0x0ffffffff, 42, 1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1380; tryItOut("\"use strict\"; p0 + o2;");
/*fuzzSeed-209835301*/count=1381; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v0, o0);");
/*fuzzSeed-209835301*/count=1382; tryItOut("\"use strict\"; h0.fix = (function() { for (var j=0;j<118;++j) { f2(j%5==1); } });");
/*fuzzSeed-209835301*/count=1383; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: true, enumerable: (x % 5 != 1),  get: function() {  return evalcx(\"this.o1.a1 = new Array;\", g1); } });");
/*fuzzSeed-209835301*/count=1384; tryItOut("/*tLoop*/for (let w of /*MARR*/[-(2**53-2), -(2**53-2)]) { ; }");
/*fuzzSeed-209835301*/count=1385; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1386; tryItOut("/* no regression tests found */o2.o0.o1.v0 = b0.byteLength;");
/*fuzzSeed-209835301*/count=1387; tryItOut("\"use strict\"; o2.m0.has(e0);");
/*fuzzSeed-209835301*/count=1388; tryItOut("a0.forEach((function mcc_() { var kjyccz = 0; return function() { ++kjyccz; if (/*ICCD*/kjyccz % 3 == 0) { dumpln('hit!'); try { t2 = t0.subarray(5,  /* Comment */((makeFinalizeObserver('tenured')))); } catch(e0) { } i0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+(((0xfd6f4e14)-(((0x684e9f92)) ? (/*FFI*/ff(((d1)), ((((-1099511627777.0)) / ((-34359738369.0)))), ((-3.022314549036573e+23)), ((-1.9342813113834067e+25)))|0) : (0xb8671d8c))+((~~(+/*FFI*/ff(((((0xfed24647)+(0x17f1369c))|0)), ((((0xf81ae0da)) & ((0x7548535)))), ((70368744177663.0)), ((-4398046511105.0)), ((-1.03125))))) != (((0x42889525) / (0x32aa5c02)) & (((\u3056) =  /x/g )))))|0));\n    return (((((((0x7c29e32a) <= (((0xffffffff)+(0xc663d4c7)+(0xfe30d187))>>>((0x686ce1b7) / (0x10059dae))))+(0x3a9192cf)-(0xc3572ed6))|0) == ((((+abs(((4277)))) < (+/*FFI*/ff(((~((0xe51a77dd)-(0xf8e86c7e)-(0x5845dfd4)))))))) & (((0x5fe3d47d) == (0xfdc671b1))+((((0x1a637f83) % (0xfca487ee))>>>((0x86d91eb4)+(0x447974d0)-(0x593f2f72))) == (((0xfecfe4dd)-(0xffffffff))>>>((0x2a773ffa) / (0x654d0245)))))))))|0;\n  }\n  return f; })(this, {ff: (Math.log(-12))}, new ArrayBuffer(4096)); } else { dumpln('miss!'); try { Object.seal(s2); } catch(e0) { } try { v1 = t2.BYTES_PER_ELEMENT; } catch(e1) { } e2 = new Set(v0); } };})());");
/*fuzzSeed-209835301*/count=1389; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log10(((Math.atan2(( + x), Math.fround(Math.pow((Math.fround(Math.trunc(Math.fround(x))) >>> 0), ( + (( - (y | 0)) | 0))))) | 0) + (Math.fround((( ~ (Number.MIN_SAFE_INTEGER | 0)) | 0)) ? Math.expm1((Math.fround(Math.fround(( ! Math.fround(y)))) != x)) : Math.fround((y >>> 0))))); }); testMathyFunction(mathy2, [-0x080000001, -0x100000001, Number.MIN_VALUE, -(2**53-2), -1/0, -(2**53+2), 1, 0/0, 0x080000001, 0x100000001, 0, 2**53+2, -Number.MIN_VALUE, 2**53-2, 1/0, -Number.MAX_VALUE, -0x080000000, 42, -0x07fffffff, 0.000000000000001, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x0ffffffff, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=1390; tryItOut("if(x) { if ( '' ) o2.toSource = function(y) { return 24 }; else e0.add(i1);}");
/*fuzzSeed-209835301*/count=1391; tryItOut("a1 = arguments;for (var p in t0) { try { a2 = a2.filter(f1); } catch(e0) { } a0.push(e1); }");
/*fuzzSeed-209835301*/count=1392; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((Math.imul(mathy0(Number.MAX_SAFE_INTEGER, ((Math.max((-0x0ffffffff >>> 0), 2**53+2) >>> 0) > y)), Math.max(Math.fround(( + Math.fround(x))), y)) % ( + Math.pow(( + (mathy1(x, x) | 0)), y))) | 0) % Math.max(( + ((( + ((Math.log((y | 0)) | 0) | ((x ? (y | 0) : x) | 0))) | 0) << ( + ( + (Math.tan((x | 0)) | 0))))), (((Math.imul(((y / x) | 0), ((Math.atan(x) | 0) | 0)) | 0) ** ( ~ x)) ^ Math.fround(Math.pow((Math.max(x, ((x | Math.fround(42)) >>> 0)) | 0), ((((0x100000001 >>> 0) % (Math.fround(Math.hypot((y >>> 0), (( ~ (x >>> 0)) >>> 0))) >>> 0)) >>> 0) >>> 0)))))); }); ");
/*fuzzSeed-209835301*/count=1393; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[false, {}, \"\\u625C\".__defineGetter__(\"x\", allocationMarker()), false, {}, \"\\u625C\".__defineGetter__(\"x\", allocationMarker()), function(){}, {}, false, \"\\u625C\".__defineGetter__(\"x\", allocationMarker()), \"\\u625C\".__defineGetter__(\"x\", allocationMarker())]); ");
/*fuzzSeed-209835301*/count=1394; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-209835301*/count=1395; tryItOut("\"use strict\"; {Array.prototype.unshift.apply(a2, [p2, p1, i1, b1, s1]);/*tLoop*/for (let b of /*MARR*/[e, [1],  '' , [1],  '' , [1], [1], e,  '' , e, [1],  '' ,  '' ,  '' , [1],  '' ,  '' , e,  '' , [1], e, [1],  '' , [1],  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , e,  '' , [1], e, [1], [1], [1],  '' , [1], [1],  '' ,  '' ,  '' ,  '' , e, [1], [1],  '' , [1],  '' ,  '' , [1], e, [1], e, e, [1],  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , e]) { b0 + a0; } }");
/*fuzzSeed-209835301*/count=1396; tryItOut("/*ADP-1*/Object.defineProperty(a0, 8, ({configurable: true, enumerable: x}));");
/*fuzzSeed-209835301*/count=1397; tryItOut("mathy2 = (function(x, y) { return ((((((Math.exp(( + y)) | 0) === ((( - ( + Math.hypot(2**53, x))) >>> 0) | 0)) <= (((( + mathy0(y, ( + Math.fround(Math.atan2(Math.fround(x), Math.fround(y)))))) >>> 0) << (Math.cos(((mathy1((0 >>> 0), (Math.fround(mathy1(Math.fround(y), Math.fround(y))) >>> 0)) >>> 0) >>> 0)) | 0)) >>> 0)) | 0) ? Math.min(Math.ceil((0x100000000 >>> 0)), ((mathy0((x >>> 0), mathy0(-0x080000000, y)) >>> 0) - Math.log(( ~ Math.fround(Math.hypot(Math.fround(Math.atan2(y, Number.MAX_VALUE)), Math.fround(-0x080000000))))))) : (Math.cbrt(mathy0((Math.fround(x) & x), Number.MIN_VALUE)) ? ( + ( ! ( + y))) : Math.imul(( - Math.max((y / x), Math.fround(Math.clz32(y)))), ( - (y + x))))) >>> 0); }); ");
/*fuzzSeed-209835301*/count=1398; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (( - ((Math.hypot(y, (y ? x : 0x080000001)) >>> 0) ? Math.min((Math.atan2(y, Math.fround(x)) >>> 0), Math.fround((Math.fround(0/0) ? Math.fround(Math.asinh(y)) : (y - y)))) : x)) , ((Math.max((Math.atan2(((y >>> 2**53) | 0), Math.max(x, (-0x080000000 >>> 0))) >>> 0), ( ~ (((y | 0) ** x) | 0))) > ((Math.fround((Math.fround(y) % Math.fround(y))) >>> 0) ** ( + Math.fround(( ~ Math.fround(Math.fround(Math.min(Math.fround(( ~ y)), Math.fround(x))))))))) >>> 0))); }); testMathyFunction(mathy0, [1.7976931348623157e308, -(2**53+2), 42, -0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 0x080000000, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, -0x080000000, 0x080000001, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, 1/0, -0, -1/0, 2**53+2, Number.MIN_VALUE, Math.PI, 0, 0/0, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 2**53, -0x07fffffff, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1399; tryItOut("var v0 = t0.length\ns0 + '';\n");
/*fuzzSeed-209835301*/count=1400; tryItOut("\"use strict\"; (x)\n");
/*fuzzSeed-209835301*/count=1401; tryItOut("a2.shift();");
/*fuzzSeed-209835301*/count=1402; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = ((((Int32ArrayView[((((0xf848bcd7)-(0xabf2667b)) >> ((0xf96c9e3b)+(-0x4c3b4a9))) % (((0x2594982b) % (0x0)) | (-0x21ba5*(0xa4aad25e)))) >> 2])) << ((((((d0) > (((-2147483648.0)) * ((-2199023255553.0))))) >> (((0xc553afb6) == (0x9853afeb))+((((0xe8ef9411))>>>((0x4b3f6656)))))))*-0xaf4f2)));\n    }\n    i1 = (0x4fd7eb27);\n    return +((NaN));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var glnzjl = x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: mathy3, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function  x (...x) \"\" , hasOwn: function() { return false; }, get: undefined, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: function() { return []; }, }; })( '' ), String.prototype.charCodeAt, Function); (eval)(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[{}, {}, {}, (0/0), {}, (0/0), {}, {}, (0/0), {}, (0/0), {}, {}, (0/0), {}, {}, {}, (0/0), {}, {}, (0/0), {}, (0/0), {}, {}, (0/0), {}, (0/0), (0/0), (0/0), {}, {}, (0/0), {}, {}, (0/0), (0/0), (0/0), (0/0), (0/0), {}, (0/0), {}, {}, (0/0), {}, (0/0), {}, {}, (0/0), {}, {}, (0/0), (0/0), {}, (0/0), {}, (0/0), (0/0), {}, (0/0), {}, {}, (0/0), (0/0), (0/0), {}, {}, {}, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), {}, {}, {}, {}, (0/0), {}, {}, (0/0), {}, {}, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), {}, {}, {}, {}, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), {}, (0/0), {}, (0/0), (0/0), {}, (0/0), (0/0), {}, (0/0), (0/0), (0/0), {}, (0/0), {}, (0/0), {}, {}, {}, (0/0), (0/0), {}, (0/0), {}, (0/0), {}, (0/0), (0/0), {}, {}]); ");
/*fuzzSeed-209835301*/count=1403; tryItOut("\"use strict\"; Array.prototype.sort.apply(a1, []);");
/*fuzzSeed-209835301*/count=1404; tryItOut("mathy0 = (function(x, y) { return (Math.hypot((((( ~ ((y * -0x100000001) >>> 0)) >>> 0) * ((((-Number.MAX_SAFE_INTEGER >>> 0) < (Math.atan(y) >>> 0)) >>> 0) >= y)) | 0), Math.fround(Math.sinh(Math.log10(1.7976931348623157e308)))) << (Math.max(Math.log(x), ((( + Math.log10(y)) === ( + (( + 1) ? x : ( + y)))) | 0)) | 0)); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -(2**53), 0, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, 0x100000001, -0x100000000, 2**53-2, -(2**53+2), Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, -1/0, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 2**53, -0, 42, -Number.MIN_SAFE_INTEGER, 1/0, 1, 0x07fffffff, -(2**53-2), -0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-209835301*/count=1405; tryItOut("mathy1 = (function(x, y) { return (Math.expm1((Math.fround(Math.pow(Math.fround(Math.max(Math.fround(( + (Math.atan2(y, (x == ( + -0x100000000))) | y))), Math.sin(( ~ Math.fround(( ! y)))))), (Math.exp(x) | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [-(2**53+2), 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53-2), 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, Number.MIN_VALUE, -0x100000001, -0x100000000, -0, 1, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, 2**53, 0.000000000000001, 0x0ffffffff, 0x080000000, -0x080000001, -Number.MAX_VALUE, -(2**53), 1/0, Math.PI, -0x07fffffff, 0x100000001]); ");
/*fuzzSeed-209835301*/count=1406; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + ( ~ (( ~ Math.fround((Math.imul((Math.cos((y | 0)) | 0), ( + Math.trunc(Math.fround(Math.fround((Math.fround(( ! y)) , -1/0)))))) != Math.fround(((x << ((((((0x080000001 | 0) ? ((-0 << 0x07fffffff) >>> 0) : (x | 0)) | 0) | 0) - (Math.atan2((y | 0), (x | 0)) | 0)) | 0)) >>> 0))))) | 0))); }); testMathyFunction(mathy0, [Math.PI, 0, 0/0, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, -0x100000000, 1, -(2**53), -(2**53-2), 1/0, 2**53, -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, -0x080000000, -0x080000001, 1.7976931348623157e308, 2**53+2, 0x100000001, 0x07fffffff, 0x0ffffffff, 42, 0x100000000, -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-209835301*/count=1407; tryItOut("v2 + g2.o1.b1;");
/*fuzzSeed-209835301*/count=1408; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1409; tryItOut("if((c) = --x) {m2.set(i2, );print(x()); } else  if (c) {h1 = g2.objectEmulatingUndefined();b0 + ''; } else print(new Element(\"\\uFF43\"));");
/*fuzzSeed-209835301*/count=1410; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[0x40000001, 2**53+2, 0x40000001, (1/0), (1/0), 0x40000001, 2**53+2, 2**53+2, (1/0), (1/0), 2**53+2, 2**53+2, (1/0), 0x40000001, 2**53+2, 2**53+2, 0x40000001, (1/0), 0x40000001, 2**53+2, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 2**53+2, (1/0), (1/0), (1/0), (1/0), (1/0), 0x40000001, (1/0), 0x40000001, 2**53+2, (1/0), (1/0), 0x40000001, (1/0), 0x40000001, 0x40000001, (1/0), 2**53+2, 0x40000001, (1/0), 0x40000001, (1/0), 2**53+2, 0x40000001, (1/0), 0x40000001, (1/0), 2**53+2, 0x40000001, 2**53+2, 2**53+2, 0x40000001, 0x40000001, 2**53+2, (1/0), 2**53+2, 2**53+2]) { v1 = evalcx(\"/*oLoop*/for (let klbtud = 0; klbtud < 4; ++klbtud) { for (var v of f2) { i0 = new Iterator(f0, true); } } \", g2); }");
/*fuzzSeed-209835301*/count=1411; tryItOut("s1 += 'x';");
/*fuzzSeed-209835301*/count=1412; tryItOut("\"use strict\"; v0 = (o2 instanceof f1);");
/*fuzzSeed-209835301*/count=1413; tryItOut("let a = /*MARR*/[ /x/g ,  /x/g , 0x100000000, 0x100000000,  /x/g ,  /x/g , 0x100000000, (0/0), (0/0),  /x/g , (0/0), 0x100000000, 0x100000000,  /x/g , 0x100000000, 0x100000000, 0x100000000, 0x100000000, (0/0), (0/0),  /x/g , (0/0),  /x/g , 0x100000000, 0x100000000, (0/0), (0/0),  /x/g , 0x100000000, 0x100000000, 0x100000000, 0x100000000, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 0x100000000, (0/0),  /x/g , 0x100000000, 0x100000000,  /x/g , 0x100000000, 0x100000000, 0x100000000, (0/0), (0/0), 0x100000000, 0x100000000, 0x100000000, (0/0), 0x100000000, (0/0), 0x100000000,  /x/g , (0/0), (0/0),  /x/g ,  /x/g , 0x100000000, 0x100000000,  /x/g ,  /x/g , (0/0), 0x100000000, 0x100000000, (0/0), (0/0), 0x100000000, (0/0),  /x/g , 0x100000000, 0x100000000, (0/0),  /x/g ,  /x/g , (0/0), 0x100000000, (0/0),  /x/g , (0/0),  /x/g ,  /x/g , 0x100000000,  /x/g , (0/0), 0x100000000, (0/0),  /x/g ,  /x/g , 0x100000000,  /x/g , (0/0), 0x100000000,  /x/g ,  /x/g , 0x100000000, (0/0)].sort;v1 = t2.length;");
/*fuzzSeed-209835301*/count=1414; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+atan2(((-268435457.0)), ((+(0.0/0.0)))));\n    i0 = (i0);\n    d1 = (+(-1.0/0.0));\n    i0 = (0xfc9a1a88);\n    (Int16ArrayView[1]) = ((x));\n    {\n      (Float32ArrayView[((i0)-((((0xfde74d82)-(0xe77c56c2)) << ((Uint8ArrayView[4096]))))+(i0)) >> 2]) = ((delete window.get));\n    }\n    {\n      (Float64ArrayView[((0x15b68e13) % (((!(0xb8741b5f))+(0xffffffff)) | ((/*FFI*/ff(((67108865.0)))|0)))) >> 3]) = ((+(-1.0/0.0)));\n    }\n    i0 = (i0);\n    {\n      d1 = (+(~(((d1) <= (73786976294838210000.0)))));\n    }\n    i0 = (0x1527cf44);\n    i0 = (/*FFI*/ff()|0);\n    {\n      i0 = (0x58a131f0);\n    }\n    return ((((((-0x8000000)+(x))>>>((0xfaff1290))) >= (0x47086104))-((+((((((i0)*0xfffff)>>>((0x1a6c1930))) < (0xe9db6db1)))>>>((0xffffffff)))))))|0;\n    {\n      d1 = (-3.022314549036573e+23);\n    }\n    i0 = (!(i0));\n    d1 = (+((((((i0))>>>((i0)*-0xca650)))) & ((i0))));\n    return (((/*FFI*/ff(((d1)), ((d1)), (((-(/*FFI*/ff(((((0xfe6d7418)) ^ ((0xffffffff)))), (((/*MARR*/[ 'A' ].some))), ((-4611686018427388000.0)), ((2251799813685249.0)), ((-1.0625)), ((9.44473296573929e+21)), ((6.044629098073146e+23)))|0)) & ((0x5bc52618)-((((0xfe0f3afc)) & ((0x1baea11c))))))), ((((Float64ArrayView[4096])) << (((0x36f45027) ? (-0x8000000) : (0xc352e8d9))))), ((d1)), ((imul((!(0x349ed86f)), ((0x2efe6496)))|0)), ((~(-(0x12df29a7)))), ((-((3.022314549036573e+23)))), ((2049.0)), ((-1125899906842624.0)), ((1.5474250491067253e+26)))|0)*0xc8cc3))|0;\n    d1 = (Infinity);\n    i0 = (-0x8000000);\n    i0 = ((imul((i0), (/*FFI*/ff()|0))|0));\n;    d1 = (d1);\n    return (((0xf94bda15)))|0;\n  }\n  return f; })(this, {ff: new RegExp(\"(?:^[^]*{3,})|(.{3,6}|([\\\\s\\\\x10-M]{1,3})){32,}(?![^\\\\u005b\\\\D\\\\cE-\\u0090\\u40af])*?\", \"gi\")}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=1415; tryItOut("for (var v of s0) { try { o2.v0 = (i1 instanceof this.h0); } catch(e0) { } m2.set(x, v0); }");
/*fuzzSeed-209835301*/count=1416; tryItOut("/*infloop*/do break M; while((({NaN: new RegExp(\"\\\\1\\\\2+?\", \"y\")})));");
/*fuzzSeed-209835301*/count=1417; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, b0);");
/*fuzzSeed-209835301*/count=1418; tryItOut("mathy1 = (function(x, y) { return ( + (mathy0((Math.cosh((Math.sign(-Number.MIN_VALUE) | 0)) | 0), (Math.hypot(( + Math.min(( + x), x)), y) | 0)) ? (mathy0(( + ((( + ((Math.exp((( - (x >>> 0)) >>> 0)) >>> 0) < (( ~ x) | 0))) >>> 0) - Math.fround(Math.imul(x, Math.acos(( + x)))))), mathy0(mathy0(( + y), y), (Math.tanh(x) | 0))) >>> 0) : ( + Math.atan2(( + ( ! ( ! 2**53-2))), ( + Math.asin(y)))))); }); testMathyFunction(mathy1, [-0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, 42, 2**53, -(2**53), 0x080000001, -Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x100000000, 0x07fffffff, 0, 0/0, 0x080000000, 0x0ffffffff, 1.7976931348623157e308, 1, -Number.MIN_VALUE, Math.PI, -0x080000001, Number.MIN_VALUE, -0x100000001, -0x0ffffffff, -0x080000000, 2**53-2, Number.MAX_VALUE, 1/0, -(2**53-2), -1/0]); ");
/*fuzzSeed-209835301*/count=1419; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + (Math.pow(Math.max(((Math.sinh(y) == -0x100000000) | 0), (( + y) >>> 0)), ( - y)) + Math.min(((x >>> 0) % (( + Math.pow(0/0, ( + (Math.fround(((Math.round(( + y)) | 0) | 0)) | 0)))) >>> 0)), Math.fround(( - ( + y)))))); }); testMathyFunction(mathy4, [-0x080000001, -0x07fffffff, -(2**53+2), -(2**53), -Number.MIN_SAFE_INTEGER, 1, 0x080000000, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 0x080000001, 0.000000000000001, 1.7976931348623157e308, 42, 0x100000000, Number.MIN_SAFE_INTEGER, 1/0, 0, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, -0x0ffffffff, -0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, -0, 0x07fffffff, -0x080000000, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 2**53]); ");
/*fuzzSeed-209835301*/count=1420; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1421; tryItOut("\"use strict\"; var yrkmfo = new ArrayBuffer(8); var yrkmfo_0 = new Int16Array(yrkmfo); var yrkmfo_1 = new Float64Array(yrkmfo); yrkmfo_1[0] = 1305410705; var yrkmfo_2 = new Uint32Array(yrkmfo); yrkmfo_2[0] = -0; var yrkmfo_3 = new Uint8ClampedArray(yrkmfo); print(yrkmfo_3[0]); yrkmfo_3[0] = 7; var yrkmfo_4 = new Uint8Array(yrkmfo); print(yrkmfo_4[0]); yrkmfo_4[0] = 25; var yrkmfo_5 = new Uint16Array(yrkmfo); Array.prototype.pop.apply(a1, [m2, s0]);print(yrkmfo_2[6]);a1[2] = null;t1 = t1.subarray(0, 17);");
/*fuzzSeed-209835301*/count=1422; tryItOut("\"use strict\"; /*RXUB*/var r = this; var s = \"\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=1423; tryItOut("\"use strict\"; ;");
/*fuzzSeed-209835301*/count=1424; tryItOut("\"use strict\"; ;");
/*fuzzSeed-209835301*/count=1425; tryItOut("e1.has(f1);");
/*fuzzSeed-209835301*/count=1426; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ((2**53 ** ( ~ (( ! (-(2**53+2) | 0)) | 0))) | Math.cosh(((-0x100000001 | 0) ^ (mathy0(((( + -0) << ( + (y ^ -(2**53+2)))) | 0), -Number.MAX_VALUE) | 0))))); }); ");
/*fuzzSeed-209835301*/count=1427; tryItOut("mathy0 = (function(x, y) { return Math.ceil((Math.atan2(( + ( ! Math.atan2(Math.fround((Math.log10(-Number.MAX_SAFE_INTEGER) | 0)), Math.fround(( ! x))))), (( - (Math.acosh(( + ( + x))) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x100000000, 1, 2**53-2, -0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -0x080000001, -1/0, -0, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), 42, 2**53+2, 0.000000000000001, Math.PI, 0, -Number.MIN_VALUE, 0/0, 0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1428; tryItOut("/*bLoop*/for (let dwskvi = 0; dwskvi < 62; ++dwskvi) { if (dwskvi % 4 == 3) { a2 + f1; } else { ( /x/g ); }  } ");
/*fuzzSeed-209835301*/count=1429; tryItOut("e1.delete(p2);");
/*fuzzSeed-209835301*/count=1430; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\2{1}\\\\B)\", \"yim\"); var s = \"\\n\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-209835301*/count=1431; tryItOut("a0 = a0.slice(2, 12, m1);");
/*fuzzSeed-209835301*/count=1432; tryItOut("/*ODP-1*/Object.defineProperty(f1, \"callee\", ({value: (((decodeURI)(21 &&  \"\" , Math.hypot(-22, -28))) ? let (z = (makeFinalizeObserver('nursery'))) (/*FARR*/[...(-7 for each (z in z = window)), , (/*MARR*/[a].sort(String.prototype.strike)), z, (makeFinalizeObserver('tenured'))].sort) : new RegExp(\"(?:.{3,5}(?!\\\\b)[^\\ub7fc-\\\\f\\u0004-\\ub528c-\\u64be]{0,})|(([^]?))\", \"yim\") + ((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: () => null, has: undefined, hasOwn: undefined, get: ({/*TOODEEP*/})( '' ), set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: this.parseInt, }; })(eval))), writable: false, configurable: false}));");
/*fuzzSeed-209835301*/count=1433; tryItOut("g2.offThreadCompileScript(\"for (var p in this.t0) { m1 = new Map(o2.i0); }\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (yield x), sourceIsLazy: false, catchTermination: (x % 3 == 0) }));");
/*fuzzSeed-209835301*/count=1434; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((Math.imul(Math.fround(( + Math.atan((Math.fround(Math.fround(Math.acosh(( + x)))) === Math.fround(y))))), ( + ( ! x))) | 0) ? Math.imul(Math.fround(((Math.fround(Math.max(Math.fround(( ! Math.fround(( + y)))), ( + Math.imul(x, x)))) >>> ( + x)) >>> 0)), ( - Math.imul(( ! Math.imul(Math.PI, Math.hypot(-Number.MAX_SAFE_INTEGER, (y | 0)))), (((y | 0) ? ( + (( + x) && Math.atan2(-(2**53), y))) : (Math.atan2(0x080000001, 0x07fffffff) | 0)) | 0)))) : ((( + (Math.fround((( + (Math.fround((x , Math.expm1(y))) | 0)) | 0)) == Math.fround(Math.pow(1/0, Math.fround((Math.fround((Math.trunc(x) === ( + (y || x)))) ? y : Math.fround((( - (( ~ (y | 0)) | 0)) | 0)))))))) & (Math.min(Math.asinh(( + Math.max((x | 0), ((Math.pow((x >>> 0), ( + 1.7976931348623157e308)) >>> 0) | 0)))), Math.fround((((( ~ Math.PI) | 0) && (0x07fffffff | 0)) | 0))) - x)) | 0)) | 0); }); testMathyFunction(mathy0, [-0x07fffffff, -0x0ffffffff, -0x080000001, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 0x080000001, -0x100000000, 1/0, -(2**53), 0.000000000000001, 0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, -(2**53+2), 2**53-2, 0, Number.MAX_VALUE, -(2**53-2), 42, -1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -0, -Number.MIN_VALUE, 1, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000]); ");
/*fuzzSeed-209835301*/count=1435; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.min(( + Math.fround(Math.clz32(Math.fround(( ! Math.pow((Math.max((Number.MAX_VALUE >>> 0), (x >>> 0)) | 0), (Math.fround(Math.min(Math.fround(x), Math.fround(y))) | 0))))))), ( + mathy2((Math.cos(Math.max(Math.sin(0x100000001), Math.PI)) | 0), (Math.fround(mathy2(Math.fround(( ! Math.min(x, x))), Math.fround(Math.fround((Math.fround(y) , Math.fround(x)))))) | 0))))); }); testMathyFunction(mathy5, [-(2**53+2), Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, 2**53, -1/0, Number.MAX_SAFE_INTEGER, -0, 0x100000001, 42, -0x080000001, -0x100000000, 0x07fffffff, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, -0x100000001, 0x080000001, 0.000000000000001, 0, 0x100000000, Math.PI, -0x0ffffffff, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, 1/0]); ");
/*fuzzSeed-209835301*/count=1436; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x609ad67e)+(!(((-(/*FFI*/ff(((d0)), ((+((9.671406556917033e+24)))), ((-1.5111572745182865e+23)), ((4.835703278458517e+24)), ((3.0)), ((-67108863.0)), ((1.00390625)), ((-549755813888.0)), ((-9223372036854776000.0)), ((63.0)))|0))>>>((0xffffffff)+((((0xff751faa))>>>((0xe4c01d22))))))))+(0x86f4d82)))|0;\n  }\n  return f; })(this, {ff: Set}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -(2**53-2), -0x0ffffffff, 0x080000001, 0, 2**53-2, -Number.MAX_VALUE, 42, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -1/0, -0x07fffffff, 1, 1/0, 2**53, 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), -0x100000000, -0, 0x100000001, Math.PI, -Number.MIN_VALUE, 0/0, Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1437; tryItOut("m0.set(e2, p2);");
/*fuzzSeed-209835301*/count=1438; tryItOut("testMathyFunction(mathy2, [-0x080000001, -0, -0x0ffffffff, 0x100000001, 0x080000000, 0x0ffffffff, -Number.MIN_VALUE, -1/0, Number.MIN_VALUE, -(2**53+2), 0/0, 0x07fffffff, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, 1, 0x100000000, 0x080000001, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -0x080000000, Math.PI, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=1439; tryItOut("this.h1.set = (function() { for (var j=0;j<31;++j) { f2(j%3==0); } });");
/*fuzzSeed-209835301*/count=1440; tryItOut("({caller: (yield  '' ) });\nObject.prototype.watch.call(t0, \"getUTCMonth\", (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14) { var r0 = a3 / a9; var r1 = a6 / a6; var r2 = a11 & a9; var r3 = a10 + a1; var r4 = a2 & r0; var r5 = a4 % a2; a12 = 5 % a9; var r6 = a3 ^ a0; var r7 = a5 | a1; var r8 = r5 & a10; var r9 = a2 | a1; var r10 = r7 | 6; var r11 = a8 * a6; var r12 = a6 ^ a9; var r13 = a8 - a14; var r14 = a11 / r11; var r15 = r14 % a0; var r16 = r3 & 8; var r17 = 6 | r2; var r18 = 2 - a3; var r19 = a1 & a12; var r20 = r13 / a5; var r21 = 3 - r11; r13 = a0 - 2; var r22 = r19 % r20; var r23 = 2 - 1; var r24 = r8 * r3; r19 = r11 / r7; var r25 = r13 % 2; var r26 = 6 | r2; var r27 = 5 % 2; var r28 = 1 | r12; var r29 = a4 & a4; var r30 = r10 & a3; r8 = r16 * r21; var r31 = a0 | r30; var r32 = 8 / r12; var r33 = r20 / a9; var r34 = r31 % a2; var r35 = 3 & r18; print(r5); var r36 = 8 | 3; var r37 = 8 % 7; var r38 = r14 * 2; var r39 = r37 * r28; var r40 = r13 - r20; var r41 = 1 % 8; var r42 = r7 | 0; a8 = 6 * 3; var r43 = r41 & 7; var r44 = r17 / r38; r17 = 8 - r21; var r45 = 7 % a0; r30 = 8 & r13; var r46 = x & r20; r20 = r12 % 3; var r47 = r26 & r38; var r48 = 5 - r39; var r49 = 1 + 6; var r50 = 2 & r16; var r51 = r31 + r39; r8 = r24 / r9; a7 = 6 / r17; var r52 = a5 | 4; var r53 = 6 | r24; var r54 = r30 & a5; var r55 = r38 + r39; r44 = 2 / r28; var r56 = r16 & r21; var r57 = a8 % 9; var r58 = r17 - r0; var r59 = r42 ^ r25; print(r52); var r60 = r24 / r28; var r61 = 3 % r18; var r62 = r60 * r56; var r63 = r15 + 4; var r64 = r61 & r36; var r65 = r40 % a5; r53 = r59 ^ 3; var r66 = 4 + 3; r43 = r66 ^ r44; var r67 = r60 % 7; r8 = r56 - 0; r8 = r62 & a4; print(r14); a12 = a11 / x; var r68 = r63 | r40; var r69 = r38 ^ 5; var r70 = r36 + 9; var r71 = 6 & r30; var r72 = 8 & r8; print(r25); var r73 = 9 | x; var r74 = 2 + 5; var r75 = 7 & 1; r2 = r40 - r59; r45 = r34 / a5; var r76 = a3 - 9; var r77 = r36 & 2; var r78 = 8 | a5; var r79 = a14 / 4; r49 = 2 ^ r50; var r80 = 2 + 0; var r81 = r63 - r79; var r82 = a10 / 7; print(r43); var r83 = 5 ^ a1; var r84 = 7 & r70; var r85 = 1 & a8; var r86 = r41 ^ r13; print(a2); var r87 = 1 - 6; var r88 = 3 & 7; var r89 = r27 | 6; var r90 = r63 % r10; var r91 = r20 % r1; var r92 = r31 % r7; var r93 = 8 & r49; r12 = 7 & r83; r77 = a9 & a14; var r94 = a4 ^ a4; a5 = r24 & r29; var r95 = r55 / 2; var r96 = r31 ^ 2; var r97 = r75 * r59; var r98 = r5 - r76; var r99 = r32 / r49; var r100 = r17 + r26; print(r82); var r101 = 4 ^ r97; var r102 = r52 * r0; r71 = a10 | r50; var r103 = 0 - r29; r29 = 7 | r99; print(r7); var r104 = r10 / r7; var r105 = r53 + 6; print(r35); var r106 = r49 - 3; r0 = 3 | 7; var r107 = r38 - 1; var r108 = 1 % r105; var r109 = x - r63; var r110 = r52 & r76; var r111 = a7 + 5; var r112 = r40 & r16; var r113 = a6 + r43; r39 = 2 | r98; var r114 = r16 / 5; var r115 = r14 | 0; var r116 = 7 % r10; var r117 = 9 + 1; r115 = r2 - r114; var r118 = r76 / r116; var r119 = 3 | r30; r7 = 4 / r82; var r120 = a2 % r112; var r121 = r74 + r1; var r122 = r66 - r87; var r123 = r115 & 3; var r124 = 2 & r4; r86 = 8 / r93; r28 = r84 - 6; var r125 = r123 * 6; var r126 = a0 * r28; print(r15); var r127 = r56 - r84; var r128 = r9 % r30; r36 = 9 | r100; var r129 = 6 - 8; var r130 = r112 & r60; var r131 = r23 % 5; r98 = r130 | r117; var r132 = 7 & 2; var r133 = r107 * r45; var r134 = 2 - 5; var r135 = 5 | r109; var r136 = 5 + r95; var r137 = 1 - 8; r84 = 9 / r17; var r138 = r103 - r77; var r139 = 6 ^ r17; print(r5); r44 = r67 / r9; r53 = r127 | r124; var r140 = r76 ^ 3; var r141 = a5 % r6; var r142 = r113 % 0; var r143 = 6 & 7; var r144 = r136 - r5; var r145 = r109 * r118; var r146 = 4 ^ r132; var r147 = r45 + r79; var r148 = 1 - r35; var r149 = 5 + r74; r136 = r139 * r101; r8 = r45 & r96; print(r120); var r150 = 9 % r134; var r151 = r70 + r15; var r152 = 6 - r136; r35 = r41 / 9; var r153 = 2 | r0; var r154 = r112 & r130; var r155 = r56 * r58; var r156 = r77 | 5; var r157 = r129 * r61; var r158 = r120 ^ r82; r56 = r151 % r71; var r159 = 3 / r83; var r160 = 0 + 4; a4 = r128 - 3; r133 = 3 + r159; var r161 = r19 ^ r87; var r162 = r74 | r11; var r163 = r133 ^ r77; a6 = r73 + 6; var r164 = 7 / r27; r107 = 9 - r77; print(r129); r144 = 8 + r26; var r165 = r98 % r88; var r166 = r3 + 9; var r167 = r162 * r20; var r168 = 1 * r42; r113 = r102 % r138; a9 = r39 | r78; var r169 = 2 / r15; var r170 = 1 | a7; r137 = 3 * r87; var r171 = 5 + r44; var r172 = r122 / 2; var r173 = r161 - r7; r164 = 3 | 8; var r174 = r153 | r169; var r175 = r83 * r7; var r176 = 7 ^ r93; var r177 = r98 ^ r80; var r178 = r60 - r105; var r179 = r35 + r106; var r180 = r4 + r89; var r181 = 8 + r76; var r182 = r8 * r91; var r183 = r134 & r69; var r184 = 7 - r90; var r185 = 3 ^ r121; var r186 = 4 ^ 0; var r187 = a10 / r113; var r188 = r187 % r83; var r189 = 7 - r171; var r190 = 6 ^ 4; var r191 = r28 | r0; var r192 = 0 + r174; var r193 = 8 | a10; var r194 = r92 & 1; var r195 = 2 | 7; var r196 = r159 & 7; var r197 = 9 % 3; var r198 = 9 | r106; r169 = 2 - r150; print(r32); var r199 = 3 * r36; var r200 = 4 * 4; var r201 = a0 * r14; a0 = r51 | a10; var r202 = r195 * r109; var r203 = 3 - r172; var r204 = 8 ^ r198; var r205 = 6 + r119; r82 = 1 / 8; var r206 = a13 ^ r190; var r207 = 7 + r52; var r208 = r33 + r60; var r209 = r52 % r3; var r210 = 1 / 4; var r211 = r203 % r139; var r212 = 5 * r7; var r213 = 9 % r34; r70 = 8 / 0; var r214 = 5 | r184; r182 = r41 * r63; var r215 = 7 + 7; var r216 = r65 % r168; var r217 = 1 / r40; var r218 = r177 / r148; var r219 = 6 & r92; var r220 = 5 / r63; var r221 = 2 % r159; print(r38); r49 = 5 % 1; var r222 = 4 | r52; var r223 = 7 - r160; r18 = r33 / r5; var r224 = r37 & 4; r42 = 6 + r146; var r225 = a11 % r172; var r226 = 8 - 9; r34 = 5 * 9; var r227 = r76 / 5; var r228 = r184 % 0; r143 = r84 - r181; var r229 = r122 ^ r139; r24 = 4 / 9; r210 = a14 % r198; r35 = 5 / 3; print(r90); r72 = r214 & 3; var r230 = 0 * r226; var r231 = r25 | r20; var r232 = r168 / 0; var r233 = r167 & 8; var r234 = 7 & r112; var r235 = 8 | r11; a14 = r20 - r9; var r236 = 6 | r90; var r237 = 6 - r9; r54 = 6 & 2; var r238 = r73 % 6; var r239 = r130 & 7; var r240 = r45 | r45; var r241 = r24 - 4; var r242 = 9 ^ r205; var r243 = 5 * 9; var r244 = r186 % r95; var r245 = r97 ^ r22; var r246 = r78 ^ r40; var r247 = 2 / 7; r155 = 4 & r149; r6 = r87 & r220; var r248 = r33 | r72; r230 = r112 & 8; var r249 = 4 | 8; var r250 = 2 | r226; var r251 = r250 / r175; print(r182); var r252 = 7 / r79; a10 = 2 - r10; var r253 = 7 ^ 5; var r254 = r159 ^ 1; print(a2); var r255 = r151 / r41; var r256 = r212 + r72; var r257 = 6 & r55; r75 = r123 & r130; var r258 = r31 - r220; var r259 = 9 | r50; var r260 = r229 & r24; print(r249); var r261 = r154 * r233; var r262 = 9 - 5; var r263 = 3 * 8; var r264 = 0 & r235; var r265 = 9 / 3; var r266 = r55 % r27; var r267 = 4 | 6; var r268 = r244 ^ r44; var r269 = r150 - 1; var r270 = 5 & r259; var r271 = a6 ^ r267; var r272 = r181 - r45; r121 = r77 * r42; var r273 = 0 + r87; print(r196); print(r186); var r274 = r37 & 3; var r275 = r143 | r108; var r276 = r62 - r209; var r277 = a2 % r236; var r278 = r89 + r169; var r279 = a3 / 7; var r280 = r179 % r202; var r281 = 5 / r160; var r282 = r7 + r244; r281 = r199 - 4; var r283 = r99 & r253; var r284 = r130 + r5; var r285 = r154 * r204; var r286 = 7 % r98; r231 = r282 * r281; var r287 = r80 ^ r124; var r288 = 2 | 3; var r289 = 1 % r222; var r290 = r281 / r182; var r291 = 7 | 7; r211 = r73 + a6; var r292 = 1 % r77; var r293 = r29 | r87; r140 = 5 * r196; var r294 = r200 % r229; var r295 = r171 ^ r238; var r296 = r10 % r17; var r297 = r259 | r226; r84 = r185 - 3; r13 = r263 + r54; var r298 = 2 / r47; var r299 = r54 - r236; r253 = r208 + r11; var r300 = 3 % r38; var r301 = 5 - a2; var r302 = a12 % r192; r29 = 6 & r274; r152 = 9 | r202; var r303 = r284 * r19; r156 = r120 / 3; var r304 = 4 & r70; var r305 = r195 | r108; var r306 = r76 * r71; var r307 = r258 | r230; var r308 = 9 + 1; print(r243); r144 = 7 * r226; return a0; }));\n/*ADP-2*/Object.defineProperty(g0.g1.a2, v2, { configurable: this, enumerable: z, get: (function(j) { if (j) { try { print(x); } catch(e0) { } Object.defineProperty(this, \"a1\", { configurable: false, enumerable: e,  get: function() {  return Array.prototype.map.apply(a1, [(function mcc_() { var dbvgsz = 0; return function() { ++dbvgsz; if (/*ICCD*/dbvgsz % 10 == 4) { dumpln('hit!'); try { this.o1 = Object.create(\"\\uF509\"); } catch(e0) { } try { f1 = Proxy.createFunction(this.h2, f1, f0); } catch(e1) { } h2.has = f0; } else { dumpln('miss!'); try { this.v0 = a2.length; } catch(e0) { } try { t1[v1] = o2; } catch(e1) { } v2 = evalcx(\"/* no regression tests found */\", g2.g1); } };})()]); } }); } else { g1.o1.h0.get = f1; } }), set: (function() { for (var j=0;j<85;++j) { f0(j%2==0); } }) });\n\n");
/*fuzzSeed-209835301*/count=1441; tryItOut("Array.prototype.unshift.call(this.a2);");
/*fuzzSeed-209835301*/count=1442; tryItOut("\"use strict\"; ");
/*fuzzSeed-209835301*/count=1443; tryItOut("\"use strict\"; ((makeFinalizeObserver('nursery')));");
/*fuzzSeed-209835301*/count=1444; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; bailAfter(21); } void 0; }");
/*fuzzSeed-209835301*/count=1445; tryItOut("\"use strict\"; m1 = new WeakMap;");
/*fuzzSeed-209835301*/count=1446; tryItOut("m2.set(g2, s1);");
/*fuzzSeed-209835301*/count=1447; tryItOut("/*infloop*/ for  each(let x in x) print(x);for(let y in undefined) t1 + f0;");
/*fuzzSeed-209835301*/count=1448; tryItOut("\"use strict\"; print( /x/ );\nreturn  '' ;\n");
/*fuzzSeed-209835301*/count=1449; tryItOut("/*infloop*/for(([, x, ]) in ((runOffThreadScript)(function(y) { \"use strict\"; yield y; t1 = t0.subarray(18, v2);; yield y; }())))/*ODP-3*/Object.defineProperty(m0, \"toLocaleString\", { configurable: (x % 21 == 0), enumerable: (x % 22 == 9), writable: (e--), value: g1 });");
/*fuzzSeed-209835301*/count=1450; tryItOut("mathy1 = (function(x, y) { return Math.clz32((Math.fround(( - Math.fround((((0x080000000 >>> 0) >> (y | 0)) | 0)))) > Math.fround(mathy0(Math.hypot(( + Math.atan(y)), ( - Math.fround(0/0))), (Math.fround(( - ( + ( ~ x)))) << x))))); }); testMathyFunction(mathy1, [-0x080000000, 0x0ffffffff, -Number.MIN_VALUE, 0/0, 2**53, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, -0, 1/0, 2**53+2, -1/0, 0x080000000, 2**53-2, Math.PI, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53+2), 0x080000001, -0x07fffffff, 0, 0x100000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, 42, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 1]); ");
/*fuzzSeed-209835301*/count=1451; tryItOut("\"use strict\"; v1 = g0.eval(\"\\\"use strict\\\"; \\\"use asm\\\"; testMathyFunction(mathy0, [0, Number.MAX_VALUE, 0x100000001, 42, 2**53, -0x080000000, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, -1/0, -0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x080000001, 2**53+2, Number.MIN_VALUE, Math.PI, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, -Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, 2**53-2, -0x07fffffff, -0, -(2**53-2), -0x100000000, 0x080000001, 1.7976931348623157e308]); \");");
/*fuzzSeed-209835301*/count=1452; tryItOut("/*infloop*/while((true)(-7))/*bLoop*/for (var apxhai = 0; apxhai < 3; ++apxhai) { if (apxhai % 2 == 1) { /*MXX1*/o2 = g2.g2.WeakSet.length; } else { this.o2 = new Object; }  } ");
/*fuzzSeed-209835301*/count=1453; tryItOut("\"use strict\"; print(uneval(i1));");
/*fuzzSeed-209835301*/count=1454; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((Float32ArrayView[((i1)-(i1)) >> 2]));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var vunmrp = x; (yield (makeFinalizeObserver('tenured')))(); })}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53+2), -0x080000000, 2**53-2, -1/0, -Number.MIN_VALUE, 42, -0x080000001, 0.000000000000001, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 1, 0x080000001, -(2**53-2), -(2**53), 1/0, 0x0ffffffff, 2**53, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, Math.PI, 2**53+2, Number.MAX_VALUE, 0x100000000, 0x100000001, -0]); ");
/*fuzzSeed-209835301*/count=1455; tryItOut("\"use strict\"; Array.prototype.splice.call(a0, NaN, v2);");
/*fuzzSeed-209835301*/count=1456; tryItOut("mathy3 = (function(x, y) { return (((( + (( + (Math.sign(((y >= ((Math.min(y, 0x07fffffff) >>> 0) >>> 0)) == y)) | 0)) <= ( + Math.pow(Math.max(Number.MIN_VALUE, (mathy0(y, ((y - (x >>> 0)) >>> 0)) || -1/0)), Math.max(Math.min(x, y), Math.pow(((Math.fround(x) >>> mathy1(y, x)) | 0), -Number.MAX_SAFE_INTEGER)))))) | 0) % (( ! Math.fround((Math.sqrt(( + x)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x100000000, 2**53, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, Number.MAX_VALUE, -0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 2**53+2, 42, 1.7976931348623157e308, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, -(2**53), 0x100000000, -0x0ffffffff, -1/0, -Number.MAX_VALUE, 0, -0x080000000, -0x080000001, 1/0, -(2**53+2), 1, -Number.MIN_VALUE, 0x0ffffffff, Math.PI]); ");
/*fuzzSeed-209835301*/count=1457; tryItOut("/*hhh*/function wlnwqw(){this.g2.v0 = (o2.o1 instanceof f2);}wlnwqw(x.yoyo(((((( ~ Math.fround(2**53+2)) >>> 0) != (((x | 0) != (x | 0)) | 0)) >>> 0))));");
/*fuzzSeed-209835301*/count=1458; tryItOut("mathy0 = (function(x, y) { return Math.cbrt(/*RXUB*/var r = /([^])/i; var s = \"\\n\"; print(s.search(r)); ); }); ");
/*fuzzSeed-209835301*/count=1459; tryItOut("Object.prototype.watch.call(t0, \"isArray\", f2);");
/*fuzzSeed-209835301*/count=1460; tryItOut("testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x100000000, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0.000000000000001, -(2**53), -0x07fffffff, -1/0, -0x080000000, 1.7976931348623157e308, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 2**53-2, 0/0, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53+2), 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), Math.PI, 0x080000001, -0, 0, 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1461; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.pow(mathy1(mathy3(( + mathy3(Math.pow(y, ( + (y % y))), ( + Math.fround((Math.fround(x) << x))))), (Math.log2((x >>> 0)) >>> 0)), ( + Math.cosh(( + ( + (Math.fround(Math.atanh(y)) <= Math.fround(y))))))), (Math.fround(Math.cbrt(Math.fround((mathy2(((y >>> 0) / Math.fround(y)), y) * (Math.sqrt(Math.expm1(y)) >>> 0))))) | 0)); }); ");
/*fuzzSeed-209835301*/count=1462; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround(mathy0(Math.fround((((( - y) | 0) & (Math.cosh(( + x)) >>> 0)) >>> 0)), Math.fround(( - Math.asinh((Math.log2(y) >>> 0)))))) !== (mathy0((Math.pow(x, (Math.hypot(Math.imul(mathy0(Math.fround(y), x), y), -1/0) | 0)) >>> 0), (mathy0((Math.fround((Math.fround(( ! Math.fround((Math.fround(y) , (y | 0))))) ? Math.fround(Math.fround(Math.log2((Math.atanh(x) >>> 0)))) : Math.fround((y ? ((((x | 0) || Math.fround(Math.atan2(x, -0x080000000))) >>> 0) | 0) : y)))) | 0), 0x100000001) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [(new String('')), (new Boolean(false)), 1, ({toString:function(){return '0';}}), (new Boolean(true)), [], ({valueOf:function(){return '0';}}), '\\0', null, '/0/', /0/, undefined, NaN, objectEmulatingUndefined(), (new Number(-0)), 0, 0.1, '', true, (new Number(0)), [0], false, '0', ({valueOf:function(){return 0;}}), -0, (function(){return 0;})]); ");
/*fuzzSeed-209835301*/count=1463; tryItOut("v1 = o1.a2.length;function  (eval, {})\"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -17592186044417.0;\n    d0 = (d2);\n    d1 = (d0);\n    {\n      d0 = (d1);\n    }\n    d1 = (+(((0xca7593da)-((d1) >= (d2))) << (-(0xcec0fb9))));\n    d0 = (d0);\n    {\n      {\n        d0 = (NaN);\n      }\n    }\n    d0 = (NaN);\n    return +((+abs(((-((d1)))))));\n  }\n  return f;/* no regression tests found */");
/*fuzzSeed-209835301*/count=1464; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (( + Math.max(Math.min((x & x), ( + Math.fround(Math.fround(mathy2((Math.log1p(x) >>> 0), y))))), Math.min(Math.min(Math.atan2((( + Math.min(( + -Number.MAX_VALUE), x)) | 0), (x >>> 0)), ( + ( + y))), (Math.hypot((x >>> 0), (y >>> 0)) >>> 0)))) % ( + ( + ( - ( + (y.watch(\"sqrt\", y)))))))); }); testMathyFunction(mathy3, [-0x100000001, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, 1/0, 0, -Number.MAX_VALUE, 0x080000001, 1, -0x07fffffff, 0x100000000, 0x100000001, -0x100000000, -(2**53-2), -(2**53+2), 0x080000000, Math.PI, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, 0.000000000000001, -(2**53), 42, 2**53, -0x080000000, 2**53-2, 2**53+2, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-209835301*/count=1465; tryItOut("testMathyFunction(mathy3, [2**53, -0x07fffffff, -0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 2**53-2, 2**53+2, 0x100000000, -0x080000000, 1, Number.MIN_VALUE, -0, 0x0ffffffff, Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x100000000, -1/0, Number.MIN_SAFE_INTEGER, 42, 0x100000001, -(2**53+2), 0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -0x100000001, 0/0, 1.7976931348623157e308, 0, -0x080000001]); ");
/*fuzzSeed-209835301*/count=1466; tryItOut("\"use strict\"; var jjpkuz = new ArrayBuffer(3); var jjpkuz_0 = new Int16Array(jjpkuz); delete o2[\"__count__\"];print(jjpkuz_0);h2.delete = (function(j) { if (j) { m2.set(o0, t0); } else { try { i2.send(m2); } catch(e0) { } Array.prototype.unshift.call(a0, a1, o1, v0, m1, s0); } });print(++y);jjpkuz_0[0];var qgzxqo;");
/*fuzzSeed-209835301*/count=1467; tryItOut("\"use strict\"; v0 = (g0.h1 instanceof m2);");
/*fuzzSeed-209835301*/count=1468; tryItOut("\"use strict\"; for (var p in g0) { try { m0.set(p0, a0); } catch(e0) { } try { s2 += s0; } catch(e1) { } try { Array.prototype.forEach.call(a1, (function() { v0 = o2.t0.byteOffset; return a0; }), e1); } catch(e2) { } s0 = Array.prototype.join.apply(a1, [o2.s2, s2, m2, b1]); }");
/*fuzzSeed-209835301*/count=1469; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.trunc(Math.fround(Math.fround(Math.imul(Math.fround(((Math.fround(mathy1((-0 | 0), ( + x))) >>> 0) - ( + Math.abs(Math.fround((Math.fround(-(2**53+2)) ? Math.fround(Number.MAX_SAFE_INTEGER) : y)))))), (( ~ (((Math.max((0x080000000 >>> 0), y) >>> 0) >>> 0) + (Math.max(1, y) >>> 0))) >>> 0))))); }); testMathyFunction(mathy5, [42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, 1, -0x0ffffffff, 2**53+2, 0/0, 2**53-2, -0x080000001, -Number.MIN_VALUE, -(2**53+2), Math.PI, 1.7976931348623157e308, 0, 0x080000000, -0x080000000, -1/0, -Number.MAX_VALUE, 1/0, -0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), -0, 0x100000001, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, 0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-209835301*/count=1470; tryItOut("\"use strict\"; /*oLoop*/for (var dcdujf = 0, 'fafafa'.replace(/a/g, \"\\uBC74\".valueOf); dcdujf < 18; ++dcdujf) { /*RXUB*/var r = /(?:(\\n|(?![\\\u0005-\\u0029\u8bef\\S])[^](?=[^\\cO\\S\\S]){4})*(?:$\u2aa2[^][^](?=\\b){2,4}|[^\\x3B-\\ub7F0\\W\\b-\\cN\\D]+))/ym; var s = (uneval({x: x} = \u000d[])); print(r.test(s)); print(r.lastIndex);  } ");
/*fuzzSeed-209835301*/count=1471; tryItOut("\"use strict\"; m0.has(v0);");
/*fuzzSeed-209835301*/count=1472; tryItOut("m1.has(o2);");
/*fuzzSeed-209835301*/count=1473; tryItOut("mathy4 = (function(x, y) { return (Math.atan2((Math.pow((Math.fround((Math.fround(((y >>> 0) - (Math.max((y | 0), y) | 0))) - ( ~ ( + ( + (( + (((y >>> 0) ? (x >>> 0) : (42 >>> 0)) >>> 0)) ? y : ( + 1.7976931348623157e308))))))) > ( ! ((Math.cos((0.000000000000001 | 0)) | 0) | 0))), (Math.atan2(Math.sinh(( - x)), ( - y)) | 0)) | 0), (( + Math.log1p(Math.fround(( + Math.sinh(( + y)))))) | 0)) | 0); }); testMathyFunction(mathy4, [-(2**53+2), -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 42, -0x07fffffff, 2**53-2, -0x080000000, -0x0ffffffff, 0x0ffffffff, 1, Number.MAX_VALUE, 0, 0x07fffffff, -Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, Math.PI, 2**53+2, 0x080000001, 2**53, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000000, -0, -1/0, 0x100000000, 0x100000001]); ");
/*fuzzSeed-209835301*/count=1474; tryItOut("Array.prototype.pop.apply(a2, [w >>>= \u3056]);");
/*fuzzSeed-209835301*/count=1475; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((( + (( + (Math.hypot(Math.atan2(2**53, Math.fround(mathy2(x, x))), (( ! (( ! Math.fround(y)) | 0)) | 0)) << ( ~ Math.atan2(Math.expm1((( + Math.max(0x080000001, ( + x))) | 0)), 2**53-2)))) + ( + ( + Math.pow((((Math.hypot((0x0ffffffff >>> 0), (( ~ (0x080000001 >>> 0)) | 0)) >>> 0) === Math.fround(x)) >>> 0), ( + Math.acosh(mathy0(Math.fround(x), x)))))))) | 0) != (((Math.fround((( ! (-0 | 0)) | 0)) , (( + ( + ((( - y) | 0) | 0))) ** Math.atan2(Math.fround(y), Number.MAX_VALUE))) ? ((mathy1((((y ? Math.sqrt(y) : x) ? -0x100000001 : 2**53) | 0), (Math.atan2(x, ((y / Number.MAX_SAFE_INTEGER) >>> 0)) | 0)) | 0) != (Math.exp(Number.MIN_SAFE_INTEGER) >>> 0)) : Math.atan2((( ! ((Math.expm1(( + ( ! ( + x)))) | 0) >>> 0)) >>> 0), (42 ? y : ( - 0x080000001)))) | 0)) | 0); }); testMathyFunction(mathy4, [(new Number(0)), '\\0', ({valueOf:function(){return '0';}}), 0.1, undefined, 0, ({valueOf:function(){return 0;}}), [], /0/, objectEmulatingUndefined(), '0', ({toString:function(){return '0';}}), '', 1, (new String('')), -0, true, false, (new Boolean(true)), null, '/0/', (new Number(-0)), NaN, [0], (new Boolean(false)), (function(){return 0;})]); ");
/*fuzzSeed-209835301*/count=1476; tryItOut("a1[window] = Math.sinh(-21) ** new ((/*RXUE*/new RegExp(\"(?=(?:\\\\x92|\\uc1e1*\\\\u0051+?(?=\\\\s)([^])|[]))\", \"yi\").exec(\"\\u00a5\")))(\nx, x);");
/*fuzzSeed-209835301*/count=1477; tryItOut("mathy0 = (function(x, y) { return ((Math.fround(((((((Math.fround(Math.hypot(Math.fround(y), Math.fround(Math.hypot(Math.atan2((-Number.MAX_SAFE_INTEGER >>> 0), 0), (Math.fround((y >>> 0)) >>> 0))))) >>> 0) ? (0x080000001 | 0) : x) | 0) >>> 0) !== (Math.log1p((( + (Math.cos(( + Math.hypot(-0, y))) >>> 0)) >>> 0)) >>> 0)) >>> 0)) / Math.fround((Math.log(Math.pow(y, x)) === (((Math.min((Number.MIN_VALUE >>> 0), (Math.fround((((y * x) >>> 0) ? Math.fround(Math.pow(((y ? x : (x >>> 0)) >>> 0), ( + Math.pow(x, x)))) : Math.fround(Number.MAX_VALUE))) >>> 0)) | 0) >>> 0) != (Math.max(Math.cos((Math.ceil(Math.max((x | 0), (-0x080000000 | 0))) | 0)), ((x >> ( + ((y >>> 0) - (y >>> 0)))) >>> 0)) >>> 0))))) | 0); }); testMathyFunction(mathy0, [0, 0x0ffffffff, -(2**53-2), 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -(2**53), -0x07fffffff, 2**53, 42, 1.7976931348623157e308, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 0x080000001, -0, Number.MIN_VALUE, 0x07fffffff, 0/0, Math.PI, -(2**53+2), -0x0ffffffff, -0x100000000, -0x080000001, 0x080000000, -Number.MIN_VALUE, -1/0, 1/0, -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1478; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( - Math.fround(( ~ Math.fround(Math.expm1(( + Math.min(( + ((0x07fffffff - ( + Math.asinh(y))) >>> 0)), ( + y)))))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, -0, 0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 0x100000000, 2**53, -Number.MIN_VALUE, 42, -0x100000000, -0x080000001, -(2**53+2), 2**53+2, 0x100000001, 2**53-2, -(2**53-2), -0x100000001, -0x07fffffff, -0x0ffffffff, -0x080000000, 0, 1/0, Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-209835301*/count=1479; tryItOut("testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, -0x100000001, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000000, -0x080000001, 0x100000001, 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, 0x080000001, -(2**53), 2**53-2, 0x07fffffff, 0x0ffffffff, -(2**53+2), -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 2**53+2, 1/0, 0/0, 1, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1480; tryItOut("\"use strict\"; /*MXX3*/g1.Uint8Array.BYTES_PER_ELEMENT = g2.Uint8Array.BYTES_PER_ELEMENT;");
/*fuzzSeed-209835301*/count=1481; tryItOut("\"use strict\"; this.s2 = '';g0.o1 = b2.__proto__;");
/*fuzzSeed-209835301*/count=1482; tryItOut("s2.valueOf = (function() { try { delete p1[\"b\"]; } catch(e0) { } try { e0 = new Set; } catch(e1) { } try { Array.prototype.sort.apply(a1, [f0]); } catch(e2) { } o0.s1 += 'x'; return e1; });");
/*fuzzSeed-209835301*/count=1483; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, 0/0, 2**53, 1/0, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 0, 0x080000000, 1, 0x100000000, -(2**53), Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, Math.PI, 2**53+2, -0x100000001, 0x07fffffff, 42, -(2**53+2)]); ");
/*fuzzSeed-209835301*/count=1484; tryItOut("m0.set(h2, a2);\nthis.a2[o2.g1.o0.v2] = x;\n");
/*fuzzSeed-209835301*/count=1485; tryItOut("s2 = '';");
/*fuzzSeed-209835301*/count=1486; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.log2((( + ((x >>> 0) == Math.fround(( + ( - ( + x)))))) % Math.asin(((( - (mathy0(y, ( - y)) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy1, [-(2**53+2), 0x0ffffffff, Number.MAX_VALUE, 0, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, 42, -0x080000001, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, 2**53-2, 0/0, 1/0, -0x0ffffffff, 0x100000000, -(2**53), 1.7976931348623157e308, Math.PI, -0, 0x080000001, 0x100000001, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, 0x07fffffff, 0x080000000]); ");
/*fuzzSeed-209835301*/count=1487; tryItOut("\"use strict\"; Object.defineProperty(this, \"v2\", { configurable: new Error(), enumerable: true,  get: function() {  return r2.sticky; } });");
/*fuzzSeed-209835301*/count=1488; tryItOut("e2.has(o1);");
/*fuzzSeed-209835301*/count=1489; tryItOut("mathy1 = (function(x, y) { return (print(y); ^ ( - ((mathy0(((( - y) >>> 0) | 0), (Math.fround((Math.fround(y) >>> y)) | 0)) | 0) | 0))); }); testMathyFunction(mathy1, /*MARR*/[ \"\" ,  \"\" , x, x, [(void 0)], x, x, [(void 0)], [(void 0)], [(void 0)],  \"\" , x, [(void 0)], [(void 0)], x, x, x, [(void 0)],  \"\" , x,  \"\" ,  \"\" ,  \"\" , x, x,  \"\" , [(void 0)],  \"\" , [(void 0)], [(void 0)],  \"\" , [(void 0)],  \"\" ,  \"\" ,  \"\" , [(void 0)], x, x, [(void 0)], [(void 0)], x, [(void 0)], x, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], x, [(void 0)],  \"\" , [(void 0)], x, x, [(void 0)], x,  \"\" , x, [(void 0)], x, x, [(void 0)],  \"\" ,  \"\" , [(void 0)], x, x, x,  \"\" , [(void 0)], [(void 0)], [(void 0)],  \"\" , [(void 0)], [(void 0)],  \"\" , [(void 0)],  \"\" , [(void 0)], [(void 0)],  \"\" ,  \"\" ,  \"\" , x,  \"\" , [(void 0)],  \"\" , x,  \"\" , [(void 0)], x, x, [(void 0)], x, [(void 0)],  \"\" , x, x, x, x,  \"\" , [(void 0)], x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, [(void 0)], [(void 0)], x,  \"\" , [(void 0)], x,  \"\" ,  \"\" ,  \"\" ,  \"\" , [(void 0)], x, x,  \"\" ,  \"\" , [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], x, x, x, x,  \"\" , x, [(void 0)],  \"\" , [(void 0)],  \"\" , [(void 0)], [(void 0)],  \"\" ,  \"\" , [(void 0)]]); ");
/*fuzzSeed-209835301*/count=1490; tryItOut("mathy0 = (function(x, y) { return ( - ( ~ ( + Math.hypot(( + Math.min(( + ( - x)), ( + Math.fround(Math.hypot(Math.fround(-0x080000000), Math.fround(x)))))), ( + ((( + ( ! y)) & y) > ( - y))))))); }); testMathyFunction(mathy0, [-0x100000001, Math.PI, -0, Number.MIN_VALUE, 0x080000000, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, 42, -0x080000000, 0x080000001, -(2**53-2), 0x07fffffff, -0x0ffffffff, -0x07fffffff, 0/0, -0x100000000, 0x100000000, 0, 0x100000001, 0x0ffffffff, 1, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 0.000000000000001, 2**53+2]); ");
/*fuzzSeed-209835301*/count=1491; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.tanh((Math.imul((( + Math.min(Math.fround((( - ((( + Math.asin(y)) & y) | 0)) | 0)), ( + Math.atan2(y, ( + Math.fround(Math.fround(Math.fround((( ! (y >>> 0)) >>> 0))))))))) | 0), (Math.max((Math.log2(( + (((mathy0(y, x) >>> 0) | y) >>> 0))) | 0), ( + ( + Math.log10((Math.hypot(2**53-2, 1.7976931348623157e308) >>> 0))))) | 0)) | 0)); }); ");
/*fuzzSeed-209835301*/count=1492; tryItOut("print(x);function w(d)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 34359738369.0;\n    var d3 = -562949953421313.0;\n    var i4 = 0;\n    return +((d0));\n  }\n  return f;v2 = true;");
/*fuzzSeed-209835301*/count=1493; tryItOut("this.g2.t0 = new Uint8ClampedArray(b1);");
/*fuzzSeed-209835301*/count=1494; tryItOut("/*infloop*/while([]\u000c.valueOf(\"number\"))m2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = (!(i0));\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: false}, new SharedArrayBuffer(4096));");
/*fuzzSeed-209835301*/count=1495; tryItOut(";");
/*fuzzSeed-209835301*/count=1496; tryItOut("a1 = Array.prototype.filter.apply(a1, [(function() { try { t2.set(a0, (4277)(delete x.eval\n)); } catch(e0) { } e0.delete(o1.t2); return i2; })]);");
/*fuzzSeed-209835301*/count=1497; tryItOut("\"use strict\"; var a = \u3056 = {};o2.i0.next();(new RegExp(\"\\\\b{1,5}\", \"gi\"));");
/*fuzzSeed-209835301*/count=1498; tryItOut("with((4277)){( /x/ ); }");
/*fuzzSeed-209835301*/count=1499; tryItOut("var wljihq = new SharedArrayBuffer(16); var wljihq_0 = new Uint8Array(wljihq); print(wljihq_0[0]); wljihq_0[0] = -7; print(x)\n");
/*fuzzSeed-209835301*/count=1500; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + ( + (Math.imul(((Math.hypot((mathy3(Math.atan2(-1/0, x), (-(2**53) | 0)) | 0), ( + Math.hypot(((Math.PI | 0) > (Number.MAX_VALUE | 0)), Math.max(Math.hypot(y, y), x)))) || Math.fround(( - ((y >>> 0) >= (0x100000000 >>> 0))))) | 0), (Math.hypot(x, Math.pow(x, Math.acosh((y >>> 0)))) >>> 0)) | 0))) >>> 0); }); testMathyFunction(mathy4, [-0x080000000, 0x100000000, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0, -0x100000000, -1/0, 2**53, 2**53-2, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 0/0, 2**53+2, Number.MIN_SAFE_INTEGER, 0, Math.PI, 0x080000000, 0x0ffffffff, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 1, 42, -(2**53+2), -0x0ffffffff, 0x100000001, 0x080000001]); ");
/*fuzzSeed-209835301*/count=1501; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i0, b1);");
/*fuzzSeed-209835301*/count=1502; tryItOut("\"use strict\"; a2 = new Array;");
/*fuzzSeed-209835301*/count=1503; tryItOut("\"use strict\"; \"use asm\"; d = let (w = x) \"\\u1479\";print(o2.e2);");
/*fuzzSeed-209835301*/count=1504; tryItOut("Array.prototype.sort.call(a1, (function mcc_() { var wmvaqc = 0; return function() { ++wmvaqc; if (/*ICCD*/wmvaqc % 3 == 2) { dumpln('hit!'); try { o1.b0 + t2; } catch(e0) { } Array.prototype.sort.apply(a0, [f2]); } else { dumpln('miss!'); e0.add(g0.p0); } };})());");
/*fuzzSeed-209835301*/count=1505; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.hypot(((Math.tan(mathy1((Math.fround(Math.atan2(Math.fround(y), Math.fround(mathy1(y, y)))) | 0), ( + Math.max(( + y), ( + y))))) ? (( - Math.fround(((x >>> 0x080000001) / Math.fround(x)))) | 0) : (Math.fround(( ~ Math.fround((( - (Number.MIN_VALUE | 0)) | 0)))) ? ((Math.atan(( + Math.min(( + 2**53), y))) | 0) ? (1 | 0) : (Math.atan(x) >>> 0)) : ( + x))) >>> 0), (Math.tanh((mathy1(Math.tan(Math.atanh((x | 0))), Math.pow(( + (0.000000000000001 + Math.fround(-Number.MAX_VALUE))), (((x | 0) >>> (( + ( ! ( + -0x0ffffffff))) | 0)) | 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [42, -(2**53-2), Number.MAX_VALUE, -0x080000001, 0x100000001, -0x100000000, -0, 0x0ffffffff, 2**53-2, 1, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, 0/0, 0x100000000, 2**53, 1/0, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 0, Math.PI, -0x07fffffff, -(2**53), -0x100000001]); ");
/*fuzzSeed-209835301*/count=1506; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1.015625;\n    var i4 = 0;\n    i4 = (0xfcb5aca7);\n    (Int16ArrayView[(-0x6c5c4*(i0)) >> 1]) = ((!((65537.0)))+((0xb5d3e150) ? (!((-17592186044417.0) < (2147483649.0))) : (i2))-((i4) ? (0x87bd09ec) : (((((1.0625) <= (70368744177665.0))*0xae1ff) << (0xfffff*(0x2bbd6806))))));\n    switch ((~(((-0x6beae4c))-((i0))-(i0)))) {\n      case 0:\n        d3 = (+tan(((0.03125))));\n      default:\n        (Float32ArrayView[(((((0xa53a5797)-(0x59006c78))>>>((0xffffffff)-(0x91e12aef)+(0x9404291f))))+(-0x8000000)-(/*FFI*/ff()|0)) >> 2]) = (((0xfd58031f)-((i0) ? (i2) : (0xd0489eda))));\n    }\n    return (((i0)*0x11f11))|0;\n  }\n  return f; })(this, {ff: arguments.callee.caller}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x07fffffff, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -(2**53-2), 1.7976931348623157e308, 42, -(2**53), 0x100000001, 2**53-2, 2**53+2, 0x080000000, -0x080000001, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), -0, -0x080000000, Number.MAX_VALUE, 0, 1/0, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, 1, Math.PI, 0.000000000000001]); ");
/*fuzzSeed-209835301*/count=1507; tryItOut("\"use strict\"; a1.push(e0, a1);");
/*fuzzSeed-209835301*/count=1508; tryItOut("testMathyFunction(mathy0, [1, 0x100000000, Math.PI, 0x07fffffff, 0x080000001, 0/0, 0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 0x100000001, -0x100000000, -Number.MAX_VALUE, 42, 2**53, 1.7976931348623157e308, -0x100000001, -(2**53+2), -(2**53), -(2**53-2), -1/0, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, 0x080000000, -0x0ffffffff, 1/0, 0.000000000000001, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1509; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-209835301*/count=1510; tryItOut("mathy2 = (function(x, y) { return Math.max((Math.acos(((mathy1((Math.pow(x, 2**53) >>> 0), (Math.round(0/0) >>> 0)) >>> 0) | 0)) | 0), Math.fround(((Math.imul(x, ( - Math.acosh(y))) >>> 0) >> Math.hypot(-Number.MAX_VALUE, Math.tanh(((((Math.fround(Math.max(Math.fround(0/0), y)) | 0) < y) | 0) | 0)))))); }); testMathyFunction(mathy2, [0x080000001, 1, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -0x080000000, 0x0ffffffff, 0x100000000, 0.000000000000001, 0x080000000, 1/0, 0x07fffffff, -0x100000000, -0x100000001, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0, 42, Number.MIN_VALUE, -(2**53-2), -(2**53+2), -(2**53), 1.7976931348623157e308, 0/0, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -0x07fffffff, -0x0ffffffff, -0x080000001, 2**53-2, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=1511; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( - (((Math.max(Math.pow(x, 0x07fffffff), (Math.fround(42) * x)) >>> 0) === ( + (( + ( + ( ~ ( + x)))) === ( + Math.abs(y))))) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0/0, -0x100000000, -(2**53-2), 0x080000000, 0x0ffffffff, -1/0, -0, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53, 1/0, 1, -Number.MAX_SAFE_INTEGER, 0, Math.PI, 2**53+2, Number.MIN_VALUE, -0x07fffffff, -0x080000000, 42, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 2**53-2, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-209835301*/count=1512; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-209835301*/count=1513; tryItOut("g1.m2.set(v0, m2);");
/*fuzzSeed-209835301*/count=1514; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-209835301*/count=1515; tryItOut("\"use strict\"; for (var p in e0) { e1.has(s0); }");
/*fuzzSeed-209835301*/count=1516; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-209835301*/count=1517; tryItOut("yield;for (var v of e2) { try { g1.e0.add(\"\\u4BDA\"); } catch(e0) { } try { for (var v of b0) { v0 = evaluate(\"h0.getOwnPropertyNames = (function() { try { print(m1); } catch(e0) { } for (var v of v2) { try { v2 = a1[\\\"arguments\\\"]; } catch(e0) { } try { a0.__iterator__ = f1; } catch(e1) { } try { i2.next(); } catch(e2) { } Array.prototype.pop.call(a0); } return a0; });\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 3 == 1), noScriptRval: (x % 32 != 9), sourceIsLazy: true, catchTermination: true, elementAttributeName: s0 })); } } catch(e1) { } try { selectforgc(o1.o2); } catch(e2) { } v2 = o2.r0.compile; }");
/*fuzzSeed-209835301*/count=1518; tryItOut("\"use strict\"; /*infloop*/for(var y; x; true) a1.forEach((function() { try { i2 + ''; } catch(e0) { } try { g2.b1 + t0; } catch(e1) { } Array.prototype.sort.apply(a0, [(function mcc_() { var hlldwp = 0; return function() { ++hlldwp; if (true) { dumpln('hit!'); try { Array.prototype.pop.apply(a0, [\"\\u965B\", h0, i0, e0]); } catch(e0) { } for (var v of a1) { try { /*RXUB*/var r = r0; var s = s0; print(s.match(r));  } catch(e0) { } /*MXX2*/g2.String.prototype.toUpperCase = m0; } } else { dumpln('miss!'); try { Array.prototype.shift.call(this.a2); } catch(e0) { } try { for (var v of b0) { try { print(uneval(i0)); } catch(e0) { } try { this.e2.has(this.p0); } catch(e1) { } h0 = {}; } } catch(e1) { } t1 = new Uint32Array(b2, 12, ({valueOf: function() { h1.valueOf = (function() { try { this.a1 = arguments; } catch(e0) { } try { s0 = new String; } catch(e1) { } try { h0.hasOwn = f1; } catch(e2) { } o0 + o1.s2; return s1; });return 13; }})); } };})()]); return f2; }), s0, s2, o2.h2, s0);");
/*fuzzSeed-209835301*/count=1519; tryItOut("h0.defineProperty = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    i0 = (1);\n    switch ((abs((~((0xa562a44b)*-0x20f9)))|0)) {\n      case -3:\n        i2 = (((2.4178516392292583e+24) != (d1)) ? (0x9974bdc9) : (-0x8000000));\n      case -1:\n        {\n          {\n            i3 = (i0);\n          }\n        }\n        break;\n    }\n    {\n      i0 = (i2);\n    }\n    (Float64ArrayView[1]) = ((2305843009213694000.0));\n    return +((1.0));\n  }\n  return f; });");
/*fuzzSeed-209835301*/count=1520; tryItOut("Array.prototype.forEach.apply(a1, [(function(j) { if (j) { try { v2 = t1.length; } catch(e0) { } try { o0 = {}; } catch(e1) { } try { o0.m2.delete(/*RXUE*/new RegExp(\"((?=\\\\b))(.)|(?!^)|\\\\s|(?:\\\\1+)\\\\3\", \"i\").exec(\"\\u00ed\\n\")); } catch(e2) { } g2.v2 + m0; } else { try { const v2 = t2.length; } catch(e0) { } try { a0[18] = x; } catch(e1) { } try { this.p1 + a1; } catch(e2) { } this.f0 = (function() { for (var j=0;j<3;++j) { f1(j%2==1); } }); } }), o2]);");
/*fuzzSeed-209835301*/count=1521; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot((( - x) ? (mathy0(( + Math.pow(Math.min(x, (y >>> 0)), Math.fround(x))), Math.fround(mathy0(Math.fround(-0x100000001), Math.fround(-(2**53-2))))) ^ ( ~ ((y === (mathy0(y, -0x080000001) >>> 0)) >>> 0))) : (Math.cos(( + x)) >>> 0)), (((Math.max(Math.fround((((y >>> 0) ? (( + y) >>> 0) : ((Math.sinh(( + (x - 0x07fffffff))) ? x : y) >>> 0)) >>> 0)), Math.fround((Math.hypot(( ! y), (Math.fround(Math.exp(Math.fround(x))) >>> 0)) >>> 0))) >>> 0) ? ((x !== y) ** (Math.fround(( - y)) !== y)) : Math.expm1(Number.MAX_VALUE)) >>> 0)); }); ");
/*fuzzSeed-209835301*/count=1522; tryItOut("testMathyFunction(mathy4, [-1/0, -(2**53), 2**53+2, -0x100000000, 0x100000001, Number.MAX_VALUE, 0, 0/0, 2**53-2, 0x080000001, 0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 2**53, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, Math.PI, 0x07fffffff, 1.7976931348623157e308, -(2**53+2), 1/0, 42, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE]); ");
/*fuzzSeed-209835301*/count=1523; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER, 0/0, -0, -0x080000000, -0x080000001, 0, -Number.MIN_VALUE, 2**53-2, -(2**53-2), 2**53, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, -0x07fffffff, Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 0x100000001, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 1, -0x100000001, 0x080000000, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, -0x100000000, 0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1524; tryItOut("m0.delete(t2);");
/*fuzzSeed-209835301*/count=1525; tryItOut("mathy5 = (function(x, y) { return ((((( + Math.sinh((( + (x >>> 42)) | 0))) | 0) !== (( + Math.sinh(x)) | (-Number.MAX_SAFE_INTEGER ? x : 2**53))) | 0) & (((((1.7976931348623157e308 | 0) / Math.fround((Math.clz32(x) | 0))) >>> 0) * Math.fround(Math.hypot(mathy3(y, x), Math.fround(( ! Math.fround(delete  /x/ )))))) >>> 0)); }); testMathyFunction(mathy5, [0x100000001, Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0/0, -0, -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 0, -0x100000000, 42, 1/0, 1.7976931348623157e308, 0x100000000, -(2**53-2), -0x07fffffff, 0x080000001, 2**53-2, -0x100000001, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, -(2**53+2), 1, Number.MIN_VALUE, 0.000000000000001, 2**53+2, Math.PI, -Number.MAX_VALUE, -0x0ffffffff, 2**53]); ");
/*fuzzSeed-209835301*/count=1526; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + Math.atan2(Math.fround(Math.fround((Math.fround(( ! mathy1(Math.fround(Math.log10((((x | 0) ? (x | 0) : ((Math.hypot(x, x) >>> 0) | 0)) | 0))), ( - x)))) % Math.fround(( ~ (Math.expm1(Math.fround(x)) >>> 0)))))), Math.fround(mathy1(((Math.fround(mathy0(Math.max(0/0, x), -(2**53))) >> ((( + Math.max(( + y), ( + Math.round(x)))) | 0) ** Math.fround(x))) | 0), (( + ( ! ( + x))) & y))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 42, -1/0, 0.000000000000001, 0x080000000, -0x100000001, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, Number.MAX_VALUE, -0, 0x080000001, -(2**53), Number.MIN_VALUE, 1/0, -0x0ffffffff, 2**53+2, 2**53, -0x080000001, 0, 0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -(2**53+2), 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, 1, -0x07fffffff, -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-209835301*/count=1527; tryItOut("(void shapeOf(Date.name++)).valueOf(\"number\") = o1.t2[({valueOf: function() { /*infloop*/M:for((Object.defineProperty(z, \"caller\", ({set: decodeURIComponent, enumerable: true}))); x; new RegExp(\"(?=[\\\\x5A-\\\\uC291\\\\d\\\\W])+?(?:(?=[\\\\cC-\\u00c9\\\\xAD-\\u00b9\\\\d\\\\G-:]|\\\\cE|^|\\\\b|\\\\s))?\", \"g\")) a1 = Array.prototype.slice.call(a2, NaN, 19, e2);return 4; }})];");
/*fuzzSeed-209835301*/count=1528; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1529; tryItOut("v1 = (i1 instanceof s0);");
/*fuzzSeed-209835301*/count=1530; tryItOut("mathy1 = (function(x, y) { return (Math.cbrt((mathy0((Math.imul(x, Math.fround((x !== (( ~ Math.trunc(x)) | 0)))) | 0), ((( + ((((( - (-(2**53) >>> 0)) >>> 0) | 0) * (x | 0)) - y)) | 0) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, [0x07fffffff, -Number.MAX_VALUE, 42, 2**53+2, -0x080000001, -1/0, -(2**53+2), -(2**53), -0x080000000, 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, -0, 0.000000000000001, 0x100000000, -0x0ffffffff, 0x100000001, 0, Math.PI, -0x100000000, 2**53, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, 1, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1531; tryItOut("\"use strict\"; for (var v of this.f2) { try { const v0 = false; } catch(e0) { } this.b2 = t2.buffer; }");
/*fuzzSeed-209835301*/count=1532; tryItOut("/*RXUB*/var r = new RegExp(\"(?!($+)|.)(?:(?:((?=([^])?|(?:^.))))?)\", \"gim\"); var s = \"\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-209835301*/count=1533; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.min(Math.fround(Math.min(Math.fround(Math.exp(Number.MAX_VALUE)), Math.fround(Math.pow(( + mathy0(( + (Math.fround(Math.hypot(Math.fround((( + 1) >>> x)), x)) ? -(2**53-2) : ((x - y) | 0))), ( + x))), Math.max((((((x | 0) >>> (x >>> 0)) | 0) - y) >>> 0), Math.fround((-(2**53) >> ( + Math.hypot(( + y), Math.fround(2**53)))))))))), ( + Math.fround(Math.log(Math.fround((((-0x080000001 >>> 0) <= (( ~ ( ! Math.fround(((( + x) && (y | 0)) | 0)))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [-1/0, 0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0/0, Math.PI, -0x0ffffffff, -0, 0x07fffffff, 42, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -Number.MAX_VALUE, 0x100000001, -0x080000000, -0x080000001, 1, 0x100000000, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 2**53+2, Number.MIN_VALUE, 0x080000000, -(2**53-2), 0.000000000000001, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, -0x100000001, 0]); ");
/*fuzzSeed-209835301*/count=1534; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(Math.abs(( - y))) != (Math.asin(mathy1(( - ( + y)), Math.atan2(y, -0x080000000))) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-209835301*/count=1535; tryItOut("var vvugii = new ArrayBuffer(2); var vvugii_0 = new Uint32Array(vvugii); vvugii_0[0] = /*FARR*/[].map(-16, this); var vvugii_1 = new Int16Array(vvugii); vvugii_1[0] = -14; var vvugii_2 = new Uint8Array(vvugii); vvugii_2[0] = 22; /*oLoop*/for (xgjcar = 0; xgjcar < 12; ++xgjcar) { a1 = arguments; } print(uneval(m2)); '' ;( \"\" );a1 = new Array;(window);");
/*fuzzSeed-209835301*/count=1536; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.hypot(Math.fround(Math.min(( + Math.hypot(Math.pow((Number.MIN_SAFE_INTEGER != x), (( ! 0x080000000) >>> 0)), Math.fround(1.7976931348623157e308))), Math.fround(Math.abs(Math.sqrt(mathy0(0x080000000, y)))))), ( + Math.tanh(mathy3(Math.pow(( + (Math.fround(mathy3(y, ( + -0x100000001))) >>> Math.fround(x))), mathy3(x, x)), ( ! ( + Math.fround(-Number.MAX_VALUE))))))); }); testMathyFunction(mathy5, [-(2**53-2), -0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -0x100000001, 0.000000000000001, 1, -0x080000001, 0/0, -1/0, Number.MIN_VALUE, 2**53+2, 0x07fffffff, 42, 1/0, -(2**53+2), 0, 0x080000000, -0, Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0x100000000, -0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 2**53, 0x100000001, Math.PI, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1537; tryItOut("Array.prototype.sort.call(a0, (function() { t0 = t2.subarray(6, ({valueOf: function() { r0 = new RegExp(\"\\\\B|.*?|([^])|[^]+\\u19c6|[^]\\\\d+(?=\\\\b|\\\\D(?!\\\\u00C6){2})(?!(?:(?=(?:.{2})))|.)\", \"g\");return 14; }})); return e0; }), ((--b))() ? ((function factorial_tail(qodfzr, avwkxt) { a1.push(g1, s2, b0, e2);; if (qodfzr == 0) { ; return avwkxt; } v2 = a0.length;; return factorial_tail(qodfzr - 1, avwkxt * qodfzr);  })(68774, 1)) :  \"\" , p2, t2, g1, g0);v2 = Object.prototype.isPrototypeOf.call(e1, a2);");
/*fuzzSeed-209835301*/count=1538; tryItOut("/*RXUB*/var r = this.r1; var s = \"\"; print(s.replace(r, Date.prototype.toLocaleTimeString)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=1539; tryItOut("a = (4277); for  each(let d in 11) {g1 = fillShellSandbox(newGlobal({ sameZoneAs: (void options('strict')), cloneSingletons: (a % 2 == 0), disableLazyParsing: new RegExp(\"\\\\D\", \"gyi\") })); }");
/*fuzzSeed-209835301*/count=1540; tryItOut("");
/*fuzzSeed-209835301*/count=1541; tryItOut("testMathyFunction(mathy3, /*MARR*/[(void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-209835301*/count=1542; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 65537.0;\n    var i4 = 0;\n    var d5 = 2.3611832414348226e+21;\n    var d6 = -137438953473.0;\n    return ((((i2)+(-0x8000000))))|0;\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=1543; tryItOut("\"use strict\"; M:switch(eval = {x, NaN}) { case (4277): break; x;break;  }");
/*fuzzSeed-209835301*/count=1544; tryItOut("\"use strict\"; with({}) return  /x/g ;");
/*fuzzSeed-209835301*/count=1545; tryItOut("s2 = new String(t0);");
/*fuzzSeed-209835301*/count=1546; tryItOut("\"use strict\"; var lyrijo = new ArrayBuffer(24); var lyrijo_0 = new Int16Array(lyrijo); var lyrijo_1 = new Uint16Array(lyrijo); print(lyrijo_1[0]); lyrijo_1[0] = -26; var lyrijo_2 = new Uint32Array(lyrijo); lyrijo_2[0] = 12; var lyrijo_3 = new Uint8Array(lyrijo); lyrijo_3[0] = -26; var lyrijo_4 = new Float32Array(lyrijo); var lyrijo_5 = new Float32Array(lyrijo); lyrijo_5[0] = 0x100000001; var lyrijo_6 = new Uint16Array(lyrijo); lyrijo_6[0] = 2; print( /x/ );/*ODP-2*/Object.defineProperty(p2, \"anchor\", { configurable: true, enumerable: true, get: (function() { for (var j=0;j<134;++j) { f2(j%4==1); } }), set: (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((0x9c94a9a2)-((+(((i0)-(0xf9fc6f0f))>>>((i0)+((0xa1321bea))))) >= ((+tan(((-0.125)))) + (((d1)) % ((((4.835703278458517e+24)) * ((-1.25)))))))-(0xb2bae563)))|0;\n  }\n  return f; }) });h0.iterate = f2;true;new RegExp(\"$|\\\\1{1}|\\\\3+?\", \"y\");o0.toString = (function() { /*ODP-2*/Object.defineProperty(t2, \"reduce\", { configurable:  /x/g , enumerable: true, get: (function() { try { for (var p in g2) { try { h1.hasOwn = f0; } catch(e0) { } print(uneval(e1)); } } catch(e0) { } Array.prototype.splice.call(a1, -3, this, f1); return f2; }), set: (function(j) { if (j) { try { /*ODP-3*/Object.defineProperty(e2, new String(\"-12\"), { configurable: false, enumerable: false, writable: (x % 73 == 21), value: t1 }); } catch(e0) { } try { h2.defineProperty = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var cos = stdlib.Math.cos;\n  var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-0.015625));\n    i0 = ((~((!(i0))+(i0))) >= (~~(d1)));\n    {\n      i0 = (i0);\n    }\n    {\n      i0 = ((eval(\"for (var p in e2) { v2 = new Number(this.e2); }\", d)));\n    }\n    return +((-268435457.0));\n    {\n      i0 = (i0);\n    }\n    (Float64ArrayView[2]) = ((+(0.0/0.0)));\n    d1 = (8388609.0);\n    (Uint8ArrayView[1]) = ((Uint8ArrayView[1]));\n    i0 = (((4277)) != (abs((abs(((((-0x8000000) ? (0x223ac6d4) : (0xff4e4448))-((d1) >= (+cos(((255.0)))))) >> ((Uint16ArrayView[1]))))|0))|0));\n    i0 = (i0);\n    {\n      {\n        d1 = (NaN);\n      }\n    }\n    i0 = (i0);\n    return +((+atan2(((34359738369.0)), ((+((+(1.0/0.0))))))));\n    i0 = ((~~(+abs(((+(0.0/0.0)))))));\n    {\n      i0 = (0xf0117984);\n    }\n    return +((562949953421313.0));\n  }\n  return f; }); } catch(e1) { } try { print(uneval(p1)); } catch(e2) { } s2.valueOf = (function() { try { for (var v of this.t1) { this.m2.set(v0, h0); } } catch(e0) { } try { o1.i2.next(); } catch(e1) { } m0.set(a1, v2); return this.g2.f0; }); } else { try { Array.prototype.shift.apply(g1.a0, [/\\n.|\\B$(?:\\S+){32767,32772}*|\\1*|\\d+|\\D\\w..**/gim, this.e1, i1, b1]); } catch(e0) { } f2.toSource = function  lyrijo_1 (lyrijo_6[8], eval, lyrijo_3, c, NaN, NaN, yield, lyrijo_6, ...c)\"\\uA610\"; } }) }); return p1; });print(window);for (var p in a0) { v1 = f1[\"toLocaleString\"]; }g0.s2 = '';p0.valueOf = 3.entries;");
/*fuzzSeed-209835301*/count=1547; tryItOut("testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x080000000, 1, -1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 2**53, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -(2**53-2), -0, -(2**53), Number.MIN_VALUE, 0x0ffffffff, -0x100000000, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, -0x080000001, 1/0, Number.MAX_VALUE, 0, -0x100000001, Math.PI, -0x07fffffff, 0x100000000, 0/0, -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-209835301*/count=1548; tryItOut("m2 = new Map;");
/*fuzzSeed-209835301*/count=1549; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-209835301*/count=1550; tryItOut("a2.shift();");
/*fuzzSeed-209835301*/count=1551; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log1p(Math.atanh(mathy1((Math.fround(mathy1(Math.fround(x), Math.fround(0x100000000))) >= y), ( ! ( + Math.hypot(x, x)))))); }); testMathyFunction(mathy2, [42, -1/0, -(2**53), Number.MIN_VALUE, -0x100000000, 0, 0/0, -0, 2**53+2, 2**53-2, -0x07fffffff, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 1/0, 0x0ffffffff, 0x07fffffff, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, 0x080000000, -(2**53+2), 0x100000000, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-209835301*/count=1552; tryItOut("");
/*fuzzSeed-209835301*/count=1553; tryItOut("\"use strict\"; var b = null;print(b);");
/*fuzzSeed-209835301*/count=1554; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.asin((((( + ( + Math.min(y, ((( - (y >>> 0)) >>> 0) >>> 0)))) >>> 0) && Math.cbrt(Math.fround(Math.acosh(( + y))))) >>> 0)); }); testMathyFunction(mathy5, [Math.PI, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 2**53, Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), -0x080000001, 0x080000000, -0x100000001, -0x080000000, 0, -0x07fffffff, -Number.MIN_VALUE, 0/0, -0x100000000, 0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), 1, 2**53-2, Number.MAX_VALUE, 0x100000000, 0x100000001, 1/0, -1/0, -(2**53), 2**53+2]); ");
/*fuzzSeed-209835301*/count=1555; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-209835301*/count=1556; tryItOut("\"use strict\"; m2.get(o1);");
/*fuzzSeed-209835301*/count=1557; tryItOut("s1.__proto__ = a2;print(eval(\" '' \", 18));");
/*fuzzSeed-209835301*/count=1558; tryItOut("\"use strict\"; for (var p in o1) { try { e2.add(v0); } catch(e0) { } try { /*RXUB*/var r = r2; var s = this.s0; print(r.exec(s));  } catch(e1) { } try { v1 = g2.eval(\";function x(x) { \\u000dv2 = g2.eval(\\\"print(x);\\\"); } /*RXUB*/var r = r0; var s = s2; print(s.match(r)); print(r.lastIndex); \\nthis.o1.f2(f1);\\n\"); } catch(e2) { } h0.defineProperty = g2.f2; }");
/*fuzzSeed-209835301*/count=1559; tryItOut("t1.set(g2.t0, 13);");
/*fuzzSeed-209835301*/count=1560; tryItOut("/*MXX3*/o2.g1.ArrayBuffer.isView = g1.ArrayBuffer.isView;");
/*fuzzSeed-209835301*/count=1561; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( ~ Math.tan(( + Math.atan(y)))) <= Math.sqrt(Math.imul((( ! Math.log1p((Math.min((( ! 0x100000000) | 0), (mathy0(x, 0) >>> 0)) | 0))) | 0), (( - ((Math.tanh((y | 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy1, [0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, Math.PI, -0x080000001, 0.000000000000001, -0, -Number.MAX_VALUE, -(2**53-2), -0x07fffffff, -(2**53+2), Number.MAX_VALUE, 0x0ffffffff, 1, Number.MIN_VALUE, 0x07fffffff, 1/0, 2**53-2, 0, 2**53+2, 0x080000000, 0x100000000, -0x100000000, 1.7976931348623157e308, -0x080000000, 0/0, 42, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53), 2**53]); ");
/*fuzzSeed-209835301*/count=1562; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy1((( - (Math.ceil(x) >>> 0)) >>> 0), (((Math.fround(Math.imul(Math.log2((Math.fround(x) - x)), ( ! ((( + (( ! y) >>> 0)) >>> 0) | 0)))) << Math.fround(( + x))) | 0) >>> 0)); }); testMathyFunction(mathy4, ['\\0', /0/, ({toString:function(){return '0';}}), (new Boolean(true)), 1, '', NaN, -0, true, objectEmulatingUndefined(), [0], (new Number(-0)), '/0/', (new Number(0)), false, ({valueOf:function(){return 0;}}), [], 0, (function(){return 0;}), ({valueOf:function(){return '0';}}), 0.1, null, (new String('')), undefined, '0', (new Boolean(false))]); ");
/*fuzzSeed-209835301*/count=1563; tryItOut("\"use strict\"; let (eval, c = d = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: window, enumerate: function() { return []; }, keys: undefined, }; })( /x/g ), Math.round(-8).toUpperCase, function(y) { return x }), finzuv, x, nvtqlv, uroyxd, x, this, x, x) { e2.has(h0); }");
/*fuzzSeed-209835301*/count=1564; tryItOut("a2 = arguments;");
/*fuzzSeed-209835301*/count=1565; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! ( + ( ! ( ~ mathy0(Math.fround((Math.imul((y >>> 0), (y >>> 0)) >>> 0)), ((mathy0((0x100000001 >>> 0), (y >>> 0)) >>> 0) >>> 0)))))); }); testMathyFunction(mathy1, [-(2**53+2), -0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x100000000, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, 1, -0x100000001, -0, -0x07fffffff, 2**53, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, Math.PI, 42, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, 2**53+2, 0x080000001, -1/0, 0]); ");
/*fuzzSeed-209835301*/count=1566; tryItOut("v0 = (t2 instanceof o1);");
/*fuzzSeed-209835301*/count=1567; tryItOut("\"use strict\"; Object.seal(s0);");
/*fuzzSeed-209835301*/count=1568; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, 2**53, 0x100000001, 0x0ffffffff, -1/0, -0, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -0x100000001, -0x07fffffff, -(2**53+2), 0x080000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, 42, 2**53+2, -0x0ffffffff, Number.MIN_VALUE, Math.PI, 0, -(2**53-2), -0x100000000, -Number.MIN_VALUE, 1/0, 0x080000000, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-209835301*/count=1569; tryItOut("\"use strict\"; this.v0 = Object.prototype.isPrototypeOf.call(t1, o2.m1);");
/*fuzzSeed-209835301*/count=1570; tryItOut("/*MXX2*/g1.Proxy.name = p1;");
/*fuzzSeed-209835301*/count=1571; tryItOut("{ void 0; minorgc(true); }");
/*fuzzSeed-209835301*/count=1572; tryItOut("throw e;w = x;");
/*fuzzSeed-209835301*/count=1573; tryItOut("mathy5 = (function(x, y) { return (mathy0(Math.fround((Math.acos(x) !== Math.atanh((function(x, y) { return ( + Math.exp(Math.min(x, Number.MAX_SAFE_INTEGER))); })))), (Math.fround(Math.imul(Math.fround(( ! (((y * (( ! (2**53-2 | 0)) >>> 0)) | 0) + Math.log1p((y ? (y >>> 0) : x))))), ( + (mathy1((mathy4(Math.fround(Math.fround(Math.pow(Math.fround(x), Math.fround(x)))), (Math.min((x >>> 0), (-0x0ffffffff >>> 0)) >>> 0)) >>> 0), ((( ! ( + x)) & (Math.fround(((x | 0) - y)) >>> 0)) >>> 0)) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-209835301*/count=1574; tryItOut("/*tLoop*/for (let c of /*MARR*/[new Number(1), -0xB504F332, new Number(1), new Number(1), -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, new Number(1), -0xB504F332, new Number(1), new Number(1), -0xB504F332, new Number(1), new Number(1), -0xB504F332, new Number(1), -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, new Number(1), -0xB504F332, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -0xB504F332, new Number(1), new Number(1), -0xB504F332, -0xB504F332, -0xB504F332, new Number(1), new Number(1)]) { g2.offThreadCompileScript(\"function this.f2(o2.g1)  { \\\"use strict\\\"; yield ((d) =  /x/ ) } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (c % 3 == 0), noScriptRval: (x % 4 == 1), sourceIsLazy: true, catchTermination: true })); }");
/*fuzzSeed-209835301*/count=1575; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (0xfa6ec270);\n    (Uint8ArrayView[((((-31.0)))) >> 0]) = ((i1)+(i1));\n    i1 = (i0);\n    i0 = ((0x310c9667));\n    (Uint32ArrayView[((i0)) >> 2]) = ((0x3fa16b0f)-(i1));\n    i0 = (i0);\n    {\n      i0 = (!(i0));\n    }\n    return (((i1)+((-4097.0) > (1.00390625))-((((i1)+(i0)) & (((-36028797018963970.0) > (((+(0x10098deb))) / ((-2097153.0)))))))))|0;\n    (Int8ArrayView[2]) = (((0x570a3482))-(0xffffffff));\n    i0 = (0x2e83d37f);\n    i1 = ((((i0)+(i0))>>>((i0)+((0xf348ace7)))) <= (0xdc4ac59d));\n    (Float32ArrayView[2]) = ((-4398046511105.0));\n    i1 = (i0);\n    i0 = ((0x19487f67));\n    {\n      return ((((((/*FFI*/ff()|0)+((0xc8b7824b) == ((1.9342813113834067e+25))))>>>(((((0x32cd1f6d) % (0xb5210f20)) & (/*MARR*/[x, x, (new (/\\2/gm)()), (new (/\\2/gm)())].map))))) == (0x95438cd5))-((1.5474250491067253e+26) >= (((+/*FFI*/ff(((~([(4277)]))), ((-1.5474250491067253e+26)), ((((-8796093022209.0)) - ((-9223372036854776000.0)))), ((((0xfc306e7b)) ^ ((0xf9a413ac)))), ((-0.001953125))))) - ((-2147483649.0))))))|0;\n    }\n    i1 = ((null) <= (536870913.0));\n    i1 = ((0x6546998f) >= ((((-131071.0)))>>>(((((0x93a12aa1))>>>((0xa3dcec90))) <= (((0xffffffff))>>>((0xfaae3bb2))))+(i0)-((((0xf852fb26)) << ((0xffffffff))) != (((-0x8000000)) ^ ((0xaf2957c2)))))));\n    (Uint8ArrayView[(((4277))+((i0) ? (i1) : (i1))) >> 0]) = ((0xffffffff));\n    {\n      i1 = (i1);\n    }\n    {\n      i0 = (((((-68719476737.0) > (((-(((x\n))))) - ((140737488355329.0)))))>>>((/*FFI*/ff((((Infinity) + (((NaN)) - ((33554433.0))))), ((3.022314549036573e+23)), ((((-0x2038da4) ? (-0x8000000) : (0x66a9b06)) ? (/*FARR*/[...x, this.__defineSetter__(\"e\", ((new Function(\"h1.__proto__ = p0;\"))).apply), (4277)].some) : ((((0xffffffff)) ^ ((-0x8000000)))))))|0))));\n    }\n    (Uint8ArrayView[2]) = ((i0)-(/*FFI*/ff(((((i0)) | ((i1)-((0xfd1d704b) ? (0xfc2fd32e) : (0x15aeb929))+(i1)))), ((~~(17179869185.0))), ((~~(((511.0)) / ((+/*FFI*/ff((((0xfd45b9b8) ? (1.001953125) : (-257.0))), ((-576460752303423500.0)), ((-295147905179352830000.0)), ((129.0)), ((-2.4178516392292583e+24)), ((-140737488355329.0)), ((1.0078125)), ((68719476735.0)), ((1125899906842625.0)), ((524289.0)), ((513.0)), ((1.0625)), ((-262145.0)), ((8.0)), ((-1073741824.0)))))))))|0)-(i0));\n    i0 = (i0);\n    {\n      i0 = (i0);\n    }\n    return (((((-(i1))>>>(-0xfdb64*(((0x85b74720))))))))|0;\n    {\n      (Uint32ArrayView[((Uint16ArrayView[1])) >> 2]) = ((((-(i1)) | (((0xffffffff) ? (0xb11f366c) : (0xffffffff))+((((+(-1.0/0.0))) * ((73786976294838210000.0))))-(i1))) < (((i1)) >> (-0x680df*(i1))))-((~((i1)))));\n    }\n    {\n      {\n        i1 = (i0);\n      }\n    }\n    return (((i1)-(i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, -(2**53+2), 2**53-2, -0x100000001, 0x080000000, -(2**53), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, -Number.MIN_VALUE, 0x0ffffffff, 2**53+2, -(2**53-2), -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 0x100000000, 0x07fffffff, -Number.MAX_VALUE, Math.PI, -0x100000000, 0, 0.000000000000001, 1, 0x080000001, -1/0, 1/0, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-209835301*/count=1576; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((((((x)>>>((((0x458627aa)) >> ((0xfb97f33e))) / (((-0x8000000)) ^ ((0xad0078f4)))))))>>>((((-(-0x8000000))|0))+((d1) > (d1)))) % (((SharedArrayBuffer)-(-0x8000000))>>>(((((0x3b410999))-((0x7fffffff) >= (0x7fffffff)))>>>((i0)+((0xffffffff) < (0x0)))) / (((0xffffffff)-(0xfa606d94))>>>((0x3bbd9309)+(0xffffffff)+(0xb165822f)))))))|0;\n  }\n  return f; })(this, {ff: URIError}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [[], ({valueOf:function(){return '0';}}), (new Number(0)), (function(){return 0;}), 0.1, /0/, null, (new Boolean(false)), false, 1, NaN, (new String('')), '', -0, '/0/', [0], (new Number(-0)), objectEmulatingUndefined(), '0', 0, ({toString:function(){return '0';}}), '\\0', true, undefined, (new Boolean(true)), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-209835301*/count=1577; tryItOut("\"use strict\"; t1 = t1.subarray(({valueOf: function() { for (var v of h2) { v0 = b2.byteLength; }return 9; }}));");
/*fuzzSeed-209835301*/count=1578; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1579; tryItOut("/*RXUB*/var r = new RegExp(\"(?![|\\\\cZ](?:([\\\\d\\\\D].?){3,4})|(?!\\\\b)|(?=(?:[^])))\", \"gy\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-209835301*/count=1580; tryItOut("\"use strict\"; h0.defineProperty = this.f2;");
/*fuzzSeed-209835301*/count=1581; tryItOut("e1.add(o2);");
/*fuzzSeed-209835301*/count=1582; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.asin((Math.max(Math.tanh(( + mathy4(Math.fround(((Math.log10((x | 0)) % (y | 0)) | 0)), ( + Math.expm1(mathy0(y, x)))))), ( + Math.imul(Math.fround(Math.sin(Math.fround(Math.ceil(y)))), ( + y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x07fffffff, 1, Number.MAX_VALUE, 2**53+2, -0, Math.PI, -0x100000001, -0x080000001, 0x080000001, 0x07fffffff, 1.7976931348623157e308, -1/0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 0x0ffffffff, -(2**53), 0, 0x100000000, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, 0x100000001, 0.000000000000001, 1/0, 2**53-2, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1583; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.pow(((Math.pow(x, Math.trunc((Math.fround(Math.cosh(x)) >>> 0))) | 0) >>> (( - (x >>> 0)) | 0)), (( - Math.imul(Math.max((( + ((y * 0) >>> 0)) != ( + ( + ( - -Number.MIN_SAFE_INTEGER)))), 0x100000001), (((x | 0) >= (Math.fround(mathy2(x, Math.fround(Math.cbrt(x)))) | 0)) | 0))) >>> 0))); }); testMathyFunction(mathy4, [-0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 1, 0, 1/0, 0x080000001, -0x100000000, Number.MAX_VALUE, -0x07fffffff, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 2**53-2, 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, -0, Math.PI, 2**53, -0x080000001, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -(2**53+2), -0x100000001, -(2**53)]); ");
/*fuzzSeed-209835301*/count=1584; tryItOut("\"use strict\"; v2 = r2.exec;with({b: (void options('strict_mode'))})v1 = a1.every((function(j) { if (j) { try { /^/i = this.t1[15]; } catch(e0) { } b2.toSource = f1; } else { a2.sort((function mcc_() { var bbrpkc = 0; return function() { ++bbrpkc; if (bbrpkc > 6) { dumpln('hit!'); try { o1 = Object.create(m0); } catch(e0) { } try { a1[5] = o0.o2.f0; } catch(e1) { } o1.r0 = /[\u8fe0]^(?!(?:\\d))+\\2*|\\1++?/ym; } else { dumpln('miss!'); try { /*MXX3*/g0.Function.prototype.apply = g1.Function.prototype.apply; } catch(e0) { } try { o2.e1.valueOf = ({/*TOODEEP*/}); } catch(e1) { } try { this.v0 = g0.t1.byteOffset; } catch(e2) { } h0 + ''; } };})()); } }));\u000c");
/*fuzzSeed-209835301*/count=1585; tryItOut("\"use strict\"; Array.prototype.sort.apply(a1, [(function() { try { o1 = f1.__proto__; } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(e2, a1); } catch(e1) { } try { v2.__proto__ = e2; } catch(e2) { } s1 += s1; return a0; }), b2, g2]);");
/*fuzzSeed-209835301*/count=1586; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( + Math.sign(( ~ Math.fround(( ~ ( + Math.tanh(((Math.fround(this) ? (0x07fffffff | 0) : (0x0ffffffff | 0)) | 0)))))))); }); testMathyFunction(mathy0, [false, '', [0], -0, '\\0', /0/, '0', NaN, (new Number(0)), (new Number(-0)), 0.1, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Boolean(true)), 1, (function(){return 0;}), [], null, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (new String('')), undefined, true, 0, '/0/', (new Boolean(false))]); ");
/*fuzzSeed-209835301*/count=1587; tryItOut("this.v1 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-209835301*/count=1588; tryItOut("mathy2 = (function(x, y) { return (((( - (Math.min((( + mathy1(( + x), ((Math.fround(y) > Math.fround(y)) >>> 0))) | 0), y) >>> 0)) != mathy0(Math.fround(mathy0(Math.fround((x ^ Math.hypot((((-0x0ffffffff >>> 0) !== y) >>> 0), x))), Math.fround(x))), Math.min((y >> (Math.clz32(0x100000000) | 0)), (((Math.log10(( + 1/0)) >>> 0) ? y : Math.ceil((x | 0))) >>> 0)))) >>> 0) || ( + ( + ( - ( + ( + ( ~ Math.fround(( ~ (( - ((( ! (x >>> 0)) >>> 0) | 0)) | 0)))))))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0.000000000000001, 0/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -0x07fffffff, 1, -0, -(2**53), -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Math.PI, 2**53-2, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0x080000000, 0, -0x080000000, Number.MIN_VALUE, 1/0, -0x100000000, 2**53+2, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), 2**53, 0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1589; tryItOut("\"use strict\"; o2.b1.toString = (function() { a0.forEach(true); throw this.g1; });");
/*fuzzSeed-209835301*/count=1590; tryItOut("Array.prototype.splice.apply(a2, [NaN, 18, o1, f1, f2]);");
/*fuzzSeed-209835301*/count=1591; tryItOut("mathy1 = (function(x, y) { return ((( + ( - ((Math.max(y, -0x0ffffffff) >>> 0) | 0))) == ((((((((((Math.imul(Math.fround(x), Math.PI) | 0) ** ( - ( + -Number.MIN_VALUE))) | 0) >= Number.MIN_SAFE_INTEGER) >>> 0) !== Math.pow(( + Math.hypot(x, ( + x))), ( + y))) | 0) | 0) ? ( + ((Math.sqrt(x) >>> 0) | x)) : Math.fround(Math.atan2(Math.fround(-0x100000001), Math.fround(Math.imul(Math.fround(Math.min(x, x)), Math.fround((x ? y : ( + mathy0(y, (y | 0)))))))))) | 0)) == ( + ( + Math.log2(( + (( + Math.hypot(((0x080000000 - y) ? Math.fround(Math.hypot(x, y)) : (y | 0)), ( + Math.abs(Math.hypot(y, (y !== y)))))) ? y : (Math.min(x, ( ! \u3056)) | 0))))))); }); ");
/*fuzzSeed-209835301*/count=1592; tryItOut("\"use strict\"; var c = c = Proxy.createFunction(({/*TOODEEP*/})(false),  \"\" , function (c) { return  /x/g  } )\u0009.unwatch(\"find\");Array.prototype.forEach.call(a2, Date.prototype.getDay.bind(m1), f2);function x(eval, y = window = x) { yield /*UUV1*/(x.tanh = Date.prototype.toLocaleTimeString) >= --NaN } this.s1 + '';");
/*fuzzSeed-209835301*/count=1593; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1594; tryItOut("m2.delete(b0);");
/*fuzzSeed-209835301*/count=1595; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1596; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-209835301*/count=1597; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( + ( + mathy0(mathy2((( + y) >>> 0), x), x)))) >>> (Math.cosh(Math.fround(mathy0(( + x), (Math.acosh(Math.fround(y)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy4, [-0, NaN, '0', 1, (new String('')), 0, (new Number(0)), (new Boolean(false)), ({valueOf:function(){return '0';}}), '/0/', [], ({toString:function(){return '0';}}), true, '\\0', (new Boolean(true)), ({valueOf:function(){return 0;}}), undefined, 0.1, (function(){return 0;}), null, '', false, /0/, (new Number(-0)), objectEmulatingUndefined(), [0]]); ");
/*fuzzSeed-209835301*/count=1598; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\1[\\s]*?|($)|\\B[^\\x8C-\\u00C2\\n-\\w\\-\\x62](?!\\B)?{1}(?=\\w|\\S\\b*?$)|(\\B|\\d?|(\\\u5033)|\\ue1BF){1,1})/im; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-209835301*/count=1599; tryItOut("m1.get(this.i0);");
/*fuzzSeed-209835301*/count=1600; tryItOut("\"use strict\"; /*bLoop*/for (ocvypq = 0; ocvypq < 51; ++ocvypq) { if (ocvypq % 39 == 33) { return; } else { v1 = (this.f2 instanceof o2.a2); }  } ");
/*fuzzSeed-209835301*/count=1601; tryItOut(";");
/*fuzzSeed-209835301*/count=1602; tryItOut("\"use strict\"; ;");
/*fuzzSeed-209835301*/count=1603; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - ( - ( ! (Math.expm1((y | 0)) | 0)))); }); testMathyFunction(mathy2, [-1/0, Number.MIN_VALUE, 2**53, 42, -0x100000000, Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, Math.PI, 0x080000001, 1.7976931348623157e308, 0, -0, -0x080000000, -(2**53-2), 0x07fffffff, -0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -0x07fffffff, 2**53-2, 0x100000001, -(2**53+2), -(2**53), 0/0, 2**53+2, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-209835301*/count=1604; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1605; tryItOut("e2.add(true);");
/*fuzzSeed-209835301*/count=1606; tryItOut("this.v0.valueOf = (function() { for (var j=0;j<10;++j) { f1(j%2==1); } });");
/*fuzzSeed-209835301*/count=1607; tryItOut("v0 = evaluate(\"function f2(g1.a2)  { yield e } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: \"\\u03A0\", catchTermination: true }));\n(-5);\n");
/*fuzzSeed-209835301*/count=1608; tryItOut("e0.add(e2);");
/*fuzzSeed-209835301*/count=1609; tryItOut("mathy2 = (function(x, y) { return (Math.trunc(( - Math.min(x, Math.fround(Math.ceil((x ? x : -0x080000001)))))) >>> 0); }); testMathyFunction(mathy2, [0x07fffffff, -0x07fffffff, 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 0, -(2**53+2), Number.MAX_VALUE, 42, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, 2**53, 1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 1, -0x100000001, -0, -(2**53), 0x080000000, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 2**53-2, 0.000000000000001, -0x080000001]); ");
/*fuzzSeed-209835301*/count=1610; tryItOut("i1 = a0.keys;");
/*fuzzSeed-209835301*/count=1611; tryItOut("t0[18] = (Math.acos(-16)) || ((void shapeOf((void options('strict_mode')))));");
/*fuzzSeed-209835301*/count=1612; tryItOut("/*MXX1*/o1 = g1.Function.prototype.bind;");
/*fuzzSeed-209835301*/count=1613; tryItOut("p1 = g0.objectEmulatingUndefined();");
/*fuzzSeed-209835301*/count=1614; tryItOut("h2.enumerate = f1;");
/*fuzzSeed-209835301*/count=1615; tryItOut("testMathyFunction(mathy0, [0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), -(2**53), -0, 0, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -1/0, -(2**53-2), Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 0x100000000, 0x0ffffffff, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, -0x0ffffffff, 1/0, 0x07fffffff, 0/0, 0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 42, -0x080000001, 0.000000000000001, Number.MIN_VALUE, 1]); ");
/*fuzzSeed-209835301*/count=1616; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return mathy1(Math.fround(( ~ Math.min(mathy1((mathy1(-(2**53+2), ((( + (x | 0)) | 0) >>> 0)) >>> 0), y), y))), ( ~ (( + (((x >>> 0) !== (( ~ y) >>> 0)) >>> 0)) ? Math.fround(( - ( + ((x && (x >>> 0)) | 0)))) : mathy2(y, -Number.MAX_SAFE_INTEGER)))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, 1, 2**53+2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, 2**53-2, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), Number.MIN_VALUE, 0x080000000, -1/0, 0, 2**53, Number.MAX_VALUE, -0x0ffffffff, 0x100000000, 42, Math.PI, -(2**53), 0.000000000000001, 0x080000001, 0/0, 0x100000001, -0x100000001, 1/0, -0, -0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-209835301*/count=1617; tryItOut("h0 = {};");
/*fuzzSeed-209835301*/count=1618; tryItOut("{print(x);throw new RegExp(\"^*?\", \"y\"); }");
/*fuzzSeed-209835301*/count=1619; tryItOut("a0.push(m0, i0, m1, this.o1);");
/*fuzzSeed-209835301*/count=1620; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Number(-0)), 1, [0], true, /0/, false, 0.1, -0, NaN, (new Number(0)), (new Boolean(true)), (function(){return 0;}), (new Boolean(false)), (new String('')), [], ({toString:function(){return '0';}}), undefined, '\\0', '0', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '/0/', null, '', ({valueOf:function(){return '0';}}), 0]); ");
/*fuzzSeed-209835301*/count=1621; tryItOut("v0 = Object.prototype.isPrototypeOf.call(g1, a1);");
/*fuzzSeed-209835301*/count=1622; tryItOut("");
/*fuzzSeed-209835301*/count=1623; tryItOut("print((4277));");
/*fuzzSeed-209835301*/count=1624; tryItOut("a1.push(m0);");
/*fuzzSeed-209835301*/count=1625; tryItOut("\"use strict\"; /*infloop*/ for  each((4277) in \u0009 /* Comment */\"\\u486E\") selectforgc(o0);");
/*fuzzSeed-209835301*/count=1626; tryItOut("\"use strict\"; Object.prototype.unwatch.call(m2, \"getMonth\");");
/*fuzzSeed-209835301*/count=1627; tryItOut("\"use strict\"; L:if((x % 6 == 3)) \u0009{o1.f1 = o2.f0; }");
/*fuzzSeed-209835301*/count=1628; tryItOut("\"use strict\"; var ihpxti = new ArrayBuffer(4); var ihpxti_0 = new Int8Array(ihpxti); ihpxti_0[0] = 986665472; var ihpxti_1 = new Int8Array(ihpxti); var ihpxti_2 = new Uint8Array(ihpxti); ihpxti_2[0] = 27; var \u000chlqvsf;print(window);v0 = Array.prototype.every.call(a1, (function mcc_() { var upekpe = 0; return function() { ++upekpe; o0.o1.f1(/*ICCD*/upekpe % 5 == 4);};})(), this.p1);this.o1.f1(f0);");
/*fuzzSeed-209835301*/count=1629; tryItOut("\"use strict\"; v1 = evaluate(\"m2.get(this.e1);\", ({ global: g1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x.watch(w << this, neuter), noScriptRval: false, sourceIsLazy: true, catchTermination:  \"\" , elementAttributeName: s2 }));");
/*fuzzSeed-209835301*/count=1630; tryItOut("Array.prototype.sort.apply(this.o0.a1, [(function() { try { v0 = t1.BYTES_PER_ELEMENT; } catch(e0) { } try { v2 = (this.g2.a0 instanceof s0); } catch(e1) { } try { e2.has(this.g1); } catch(e2) { } b0 + ''; return f0; })]);function a() /x/g v1 = r2.constructor;");
/*fuzzSeed-209835301*/count=1631; tryItOut("p0.toString = f0;");
/*fuzzSeed-209835301*/count=1632; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.exp(((((Math.imul(( + (( + (mathy1(y, y) ? ((Math.min(y, y) >>> 0) || y) : y)) >= (Math.pow(x, ( - (y | 0))) | 0))), ( + (y >> 42))) | 0) ? ((Math.fround(( + y)) !== (Math.tan((-(2**53-2) >>> 0)) < ( + Math.acos((x | 0))))) | 0) : (Math.fround(( ! ((Math.fround((((Math.hypot(2**53, Math.fround(y)) | 0) - y) , Math.fround(y))) | 0) + Math.fround(mathy3(y, ( + -Number.MAX_VALUE)))))) | 0)) | 0) | 0))); }); ");
/*fuzzSeed-209835301*/count=1633; tryItOut("a = linkedList(a, 4346);");
/*fuzzSeed-209835301*/count=1634; tryItOut("\"use strict\"; /*iii*//*oLoop*/for (var sswzju = 0; sswzju < 36; ++sswzju) { t2[({valueOf: function() { for (var v of g1) { try { t0[4] = x; } catch(e0) { } try { e1 = new Set(s0); } catch(e1) { } v0 = g1.runOffThreadScript(); }return 9; }})]; } /*hhh*/function axcluk(...d){var kinzvx = new SharedArrayBuffer(0); var kinzvx_0 = new Uint8ClampedArray(kinzvx); print(kinzvx_0[0]); kinzvx_0[0] = -5; var kinzvx_1 = new Int16Array(kinzvx); kinzvx_1[0] = -0; var kinzvx_2 = new Float32Array(kinzvx); var kinzvx_3 = new Int8Array(kinzvx); kinzvx_3[0] = 2**53; t1 = new Float64Array(o1.b0, 22, v2);}");
/*fuzzSeed-209835301*/count=1635; tryItOut("\"use strict\"; /*hhh*/function htexje(){print(b1);}htexje();(void schedulegc(g2));");
/*fuzzSeed-209835301*/count=1636; tryItOut("\"use strict\"; Object.seal(g2);");
/*fuzzSeed-209835301*/count=1637; tryItOut("if(false) p1.valueOf = (function() { h2 + this.v1; return v1; });");
/*fuzzSeed-209835301*/count=1638; tryItOut("x = eval(\"/* no regression tests found */\");let (w) { print(s1); }");
/*fuzzSeed-209835301*/count=1639; tryItOut("o1.v1 = Object.prototype.isPrototypeOf.call(g2, o2);");
/*fuzzSeed-209835301*/count=1640; tryItOut("i2 = new Iterator(o0.g1.p1);");
/*fuzzSeed-209835301*/count=1641; tryItOut("g2.e2.delete(v1);");
/*fuzzSeed-209835301*/count=1642; tryItOut("testMathyFunction(mathy5, [(new Number(0)), (function(){return 0;}), (new Boolean(false)), -0, (new Number(-0)), 0.1, true, objectEmulatingUndefined(), undefined, ({toString:function(){return '0';}}), (new String('')), ({valueOf:function(){return '0';}}), '\\0', '/0/', '', ({valueOf:function(){return 0;}}), '0', (new Boolean(true)), false, [], NaN, 0, null, /0/, [0], 1]); ");
/*fuzzSeed-209835301*/count=1643; tryItOut("mathy4 = (function(x, y) { return Math.min((Math.max(Math.fround((Math.imul(((Math.atan(x) | 0) | 0), ((x ? ( + ( + ( + x))) : x) | 0)) | 0)), Math.fround((((( + (((x | 0) ? (y | 0) : (((x ? x : x) >>> 0) | 0)) | 0)) >>> 0) >= Math.sinh(x)) >>> 0))) >>> 0), mathy2(Math.max((( + (1/0 ? y : y)) * ( + (( + mathy0(1, y)) | ( + Math.exp(( + x)))))), y), ( ! Math.fround((Math.fround(( ! Math.fround(Math.asinh(x)))) ? Math.fround(( + (y | 0))) : Math.fround(x)))))); }); ");
/*fuzzSeed-209835301*/count=1644; tryItOut("print(uneval(f0));");
/*fuzzSeed-209835301*/count=1645; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (\n(Object.defineProperty(b, new String(\"6\"), ({writable: (x % 4 != 3)}))));\n    return (((0x646e9ba6)*-0xec08c))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ \"use strict\"; t0 = new Int8Array(10);return x})()}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-209835301*/count=1646; tryItOut("t2.set(t2, 1);");
/*fuzzSeed-209835301*/count=1647; tryItOut("t0 = t0.subarray(19, v1);function b()Math.sign(9)for (var p in this.b1) { try { s1 = new String(b1); } catch(e0) { } try { g1.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e1) { } g2.m1.has(g1.p1); }");
/*fuzzSeed-209835301*/count=1648; tryItOut("e2.__proto__ = s0;");
/*fuzzSeed-209835301*/count=1649; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.asinh(((Math.fround(( ~ (( + mathy0(( + (1 + x)), (Math.imul((-(2**53+2) | 0), (x | 0)) | 0))) | 0))) ? Math.fround(( ! Math.fround(( ! (y == mathy0(Math.fround(x), Math.fround(y))))))) : Math.fround(Math.atan2(Math.fround(( ! (( + x) + y))), ( + (x | y))))) | 0)); }); testMathyFunction(mathy1, ['\\0', '/0/', 0, [0], undefined, ({valueOf:function(){return '0';}}), true, null, objectEmulatingUndefined(), (new Number(-0)), (new String('')), [], 1, /0/, '0', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), NaN, false, -0, (new Boolean(true)), (function(){return 0;}), (new Number(0)), '', (new Boolean(false)), 0.1]); ");
/*fuzzSeed-209835301*/count=1650; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(( + ( ~ ( + Math.cos(( ~ (Math.atan2((2**53 | 0), (-1/0 | 0)) | 0))))))), (Math.hypot(((Math.sinh((-Number.MIN_VALUE | 0)) ** (( + y) >>> y)) >>> 0), (( ~ x) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [false, '/0/', null, (new Boolean(false)), 1, undefined, [], '0', (new String('')), (new Boolean(true)), '', objectEmulatingUndefined(), NaN, (new Number(-0)), (new Number(0)), (function(){return 0;}), true, -0, [0], 0, /0/, ({toString:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), '\\0', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-209835301*/count=1651; tryItOut("\"use strict\"; for(let c in []);");
/*fuzzSeed-209835301*/count=1652; tryItOut("\"use strict\"; if(false) let(x = (/*MARR*/[objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0)].map), tioonc, x = new encodeURI( \"\" ), otovuy, msmfam, hokxra) ((function(){return ({}) = Math.min(-26,  '' );})());let(y = /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [1], [1],  /x/ , -0x07fffffff, [1], [1], objectEmulatingUndefined(), -0x07fffffff, [1], objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], -0x07fffffff,  /x/ , [1], [1], -0x07fffffff, [1],  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , -0x07fffffff, [1],  /x/ , objectEmulatingUndefined(), [1], -0x07fffffff,  /x/ , objectEmulatingUndefined(), -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, [1], [1], -0x07fffffff, objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], -0x07fffffff, [1], [1], -0x07fffffff,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), [1], -0x07fffffff, [1], -0x07fffffff, [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(),  /x/ , -0x07fffffff,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , -0x07fffffff,  /x/ ,  /x/ , [1], objectEmulatingUndefined(),  /x/ ,  /x/ , [1],  /x/ , -0x07fffffff, [1],  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , [1], -0x07fffffff, objectEmulatingUndefined(), [1],  /x/ , [1], -0x07fffffff,  /x/ ,  /x/ ,  /x/ , -0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), [1],  /x/ , [1], objectEmulatingUndefined(),  /x/ , -0x07fffffff, -0x07fffffff, objectEmulatingUndefined(), -0x07fffffff, -0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], -0x07fffffff, objectEmulatingUndefined(),  /x/ ,  /x/ , [1], -0x07fffffff, -0x07fffffff,  /x/ ,  /x/ ,  /x/ ,  /x/ ].filter(decodeURI,  \"\" ), b = eval(\"\\\"use strict\\\"; h0.fix = o0.f2;\", \"\\u28B6\"), window = x, window = /\\b|[\uc177=\\d]|(?:.)[^]*\\1|(?!^)*|$(?=\\W){4,8}{0}|\\u00A3|\\D[^]|\\b|\\B*?|\\2/gy) ((function(){let(x =  /x/g , itcyyp, window, x, ayoiaq, a, e, \u3056, constructor) ((function(){this.zzz.zzz;})());})());");
/*fuzzSeed-209835301*/count=1653; tryItOut("/*oLoop*/for (hrkbom = 0; hrkbom < 15; !eval(\"mathy1 = (function(x, y) { return Math.max(( + (( + Math.hypot(x, (mathy0((-0x080000000 | 0), (Math.min(Math.fround(y), Math.fround(x)) | 0)) | 0))) * ( + ( ~ (0 / (Math.pow((Math.atan2(x, mathy0(-Number.MIN_SAFE_INTEGER, x)) | 0), (( + ( + 1/0)) >>> 0)) >>> 0)))))), (Math.min((( ~ (( + (( + x) * (Math.atan2(Math.fround(y), y) | 0))) | 0)) | 0), ((( + (( + ( + ( + (Math.max(-Number.MAX_VALUE, x) - Math.atan(y))))) | 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy1, [0x100000001, 0x0ffffffff, 2**53, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, -1/0, -0x080000001, 0x080000001, -0x100000001, -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, 42, 0x07fffffff, 1/0, 0, 0x080000000, -0x07fffffff, -Number.MAX_VALUE, 1, -(2**53), 2**53-2, -Number.MIN_VALUE, 0/0]); \"), ++hrkbom) { g1.__iterator__ = Float64Array; } ");
/*fuzzSeed-209835301*/count=1654; tryItOut("let (uhdbbx, qwouvt, cdllbi, mkwelv, eval = (function ([y]) { })|=new Object(\"\\u0182\",  /x/ ), y = x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: undefined, has: function() { return false; }, hasOwn:  \"\" , get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(true), ( /x/g  instanceof )), z = (x), vzjrtp, b) { t0.__iterator__ = (function() { try { g2.__proto__ = p0; } catch(e0) { } try { var v0 = evaluate(\"function f1(m2)  { \\\"use strict\\\"; /*infloop*/for(x; [1];  /x/g ) {print(NaN); } } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (void options('strict')), catchTermination: (yield  /x/ .valueOf(\"number\")), element: g0.o1, elementAttributeName: s2 })); } catch(e1) { } g0.t0 = new Float64Array(a2); return s2; }); }");
/*fuzzSeed-209835301*/count=1655; tryItOut("/* no regression tests found */");
/*fuzzSeed-209835301*/count=1656; tryItOut("r0 = /(?=(?![^])*?|(?:^)*{0,0})*/i;");
/*fuzzSeed-209835301*/count=1657; tryItOut("with({z: \"\\u0F95\"})if((x % 3 == 1)) { if (({ get z \u3056 (\u000cx, x = (void options('strict')))allocationMarker() })) g1.g1.s1 += s0;} else let o2 = new Object;");
/*fuzzSeed-209835301*/count=1658; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-Number.MIN_VALUE, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, 0x0ffffffff, 0x100000000, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 1/0, 0/0, -(2**53), -0x080000000, -(2**53-2), 0x100000001, 42, -(2**53+2), Math.PI, -1/0, 0, -0x080000001, -0x100000001, 0x080000000, 0.000000000000001, 2**53]); ");
/*fuzzSeed-209835301*/count=1659; tryItOut("mathy3 = (function(x, y) { return ( + ( + ( + Math.max(mathy1(mathy0((y >>> 0), (Math.log1p(2**53-2) | 0)), y), Math.fround((x * Math.asinh(Math.fround(( + Math.tan(x)))))))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, Number.MIN_VALUE, 0, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, -(2**53), 0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -0x100000001, 1, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, 2**53-2, -0, 1.7976931348623157e308, Math.PI, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, 42, -Number.MIN_VALUE, 2**53, -(2**53+2), 2**53+2, 0x100000001, 1/0, -0x0ffffffff]); ");
/*fuzzSeed-209835301*/count=1660; tryItOut("m1 = new Map;");
/*fuzzSeed-209835301*/count=1661; tryItOut("mathy1 = (function(x, y) { return (((Math.imul((( + ((Math.log10((Math.hypot(( + 2**53-2), -0x080000000) >>> 0)) !== ((mathy0(x, 0x07fffffff) >>> 0) ? Math.fround(-Number.MIN_SAFE_INTEGER) : ( + mathy0(y, x)))) | 0)) | 0), ((-Number.MIN_VALUE - ( + (((x ? x : x) | 0) >>> 0))) ? ((Math.fround(Math.pow((( + mathy0((( - (y >>> 0)) >>> 0), y)) >>> 0), Math.fround(x))) <= Math.imul((( ! y) >>> 0), x)) | 0) : (Math.pow(mathy0(( ! Math.fround(y)), y), y) <= mathy0((-0x0ffffffff >>> 0), (y == ( + y)))))) | 0) < (Math.min(((-(2**53+2) ? 1 : -Number.MAX_VALUE) >>> x), Math.atan2(Math.hypot(( + 1/0), ( + Math.fround(( ! -0x07fffffff)))), ( + ( + ( + (Math.fround((x | 0)) | 0)))))) | 0)) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, 0, Math.PI, 0.000000000000001, 0x100000000, -0x080000001, Number.MAX_VALUE, 2**53-2, -0x07fffffff, -1/0, -(2**53-2), -Number.MIN_VALUE, -(2**53), 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -0x100000000, 1, -0x100000001, 2**53+2, 1/0, -Number.MAX_VALUE, -0, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53, 42]); ");
/*fuzzSeed-209835301*/count=1662; tryItOut("/*RXUB*/var r = /(?!((?:(?!\\b)?)+?){4194304})/gym; var s = \"\"; print(s.search(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
