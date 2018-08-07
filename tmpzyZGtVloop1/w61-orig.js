

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
/*fuzzSeed-248247344*/count=1; tryItOut("var gazlzz = new SharedArrayBuffer(4); var gazlzz_0 = new Int8Array(gazlzz); print(gazlzz_0[0]); gazlzz_0[0] = 24; var gazlzz_1 = new Uint16Array(gazlzz); gazlzz_1[0] = -17; var gazlzz_2 = new Int16Array(gazlzz); gazlzz_2[0] = -8; var gazlzz_3 = new Uint16Array(gazlzz); print(gazlzz_3[0]); var gazlzz_4 = new Float32Array(gazlzz); print(gazlzz_4[0]); gazlzz_4[0] = -13; var gazlzz_5 = new Uint8Array(gazlzz); gazlzz_5[0] = 10; var gazlzz_6 = new Int8Array(gazlzz); print(gazlzz_6[0]); gazlzz_6[0] = -25; var gazlzz_7 = new Int32Array(gazlzz); gazlzz_7[0] = -18; let c = /(?:(?:(?!.+|\\B*)+?))/gi;this;v1 = (this.v0 instanceof h2);/*RXUB*/var r = /(?!^|^|\\2{1}|(?!(.))\\b^+??|\\x90){2}(?=\\3)*?/gm; var s = \"\"; print(s.replace(r, (function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: /*wrap1*/(function(){ this.e0.add(o1.h0);return RegExp.prototype.exec})(), defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: /*wrap1*/(function(){ (undefined);return String.prototype.anchor})(), delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: function() { throw 3; }, }; }))); i0 + '';");
/*fuzzSeed-248247344*/count=2; tryItOut("testMathyFunction(mathy2, [-0x0ffffffff, 0x080000000, 0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, 0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, -1/0, 42, Number.MIN_VALUE, 1, -0, -(2**53-2), 0x100000000, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, 2**53, -(2**53+2), 0x100000001, 0x0ffffffff, -0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, Math.PI, -0x100000001]); ");
/*fuzzSeed-248247344*/count=3; tryItOut("mathy4 = (function(x, y) { return Math.log2(Math.fround(Math.exp(Math.max(( - (Math.imul((( + ( + ( + x))) | 0), -0x100000000) | 0)), Math.hypot(x, Math.fround(x)))))); }); ");
/*fuzzSeed-248247344*/count=4; tryItOut("print(p0);");
/*fuzzSeed-248247344*/count=5; tryItOut("\"use asm\"; NaN\u000d;");
/*fuzzSeed-248247344*/count=6; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround((Math.imul(( + ( + ( + x))), (x + x)) ? Math.fround((( + Math.pow(( - ((0 | 0) ? x : x)), Math.hypot(x, x))) | ( + Math.fround(Math.cos((Math.fround(Math.min(Math.fround(y), Math.fround(x))) ? (-0x0ffffffff | 0) : (( + x) | 0))))))) : (((Math.pow((x >>> 0), (x >>> 0)) | 0) >> ((Math.atan2(((Math.cos(x) | 0) >>> 0), (-(2**53) >>> 0)) >>> 0) | 0)) | 0))) == Math.fround(Math.acos(( + ( ~ (Math.round((y >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, [0x0ffffffff, 1, 0.000000000000001, 42, -0x07fffffff, -(2**53), 0x080000001, -0x100000000, -1/0, Math.PI, 2**53+2, -(2**53-2), 0/0, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 0, 0x080000000, -0x100000001, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -0, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-248247344*/count=7; tryItOut("for(let e in /*FARR*/[(z - b >>>= ( \"\"  != 9))]) let(npgpvo, x, utnhow, wqojfo) { for(let a of /*MARR*/[new Number(1.5), e, e, e, e, e, e, e, e, e, e, e, e, e, e, e, e, e, new Number(1.5), ({a2:z2}), new Number(1.5), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), e, ({a2:z2}), e, ({a2:z2}), ({a2:z2}), new Number(1.5), e, ({a2:z2}), new Number(1.5), new Number(1.5), ({a2:z2}), e, e, new Number(1.5), new Number(1.5), new Number(1.5), e, ({a2:z2}), new Number(1.5), e, new Number(1.5), ({a2:z2}), new Number(1.5), e, e, ({a2:z2}), new Number(1.5), new Number(1.5), e, ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), e, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), e, ({a2:z2}), ({a2:z2}), ({a2:z2}), new Number(1.5), ({a2:z2}), e, e, e, ({a2:z2}), new Number(1.5), new Number(1.5), new Number(1.5), ({a2:z2}), e, new Number(1.5), ({a2:z2}), e, e, ({a2:z2}), e, ({a2:z2}), ({a2:z2}), new Number(1.5), new Number(1.5), ({a2:z2}), ({a2:z2}), e, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), ({a2:z2}), ({a2:z2}), ({a2:z2}), e, ({a2:z2}), new Number(1.5)]) return;}");
/*fuzzSeed-248247344*/count=8; tryItOut("\"use asm\"; o0 + g2;");
/*fuzzSeed-248247344*/count=9; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=10; tryItOut("\"use strict\"; with({z: x}){hgqrzl();/*hhh*/function hgqrzl(x = (yield (4277)), window){this.o1.a2.push(m2, h1);} }");
/*fuzzSeed-248247344*/count=11; tryItOut("\"use strict\"; s2.valueOf = (function(j) { if (j) { try { h0.has = g1.f1; } catch(e0) { } try { f0.toString = (function() { try { v2 = (x % 18 != 5); } catch(e0) { } Array.prototype.reverse.call(a1); return h2; }); } catch(e1) { } /*RXUB*/var r = this.r1; var s = \"\\u4400\\ufbcb\\ufbcb\\ufbcb\\ufbcb\\ufbcb\\ufbcb\\ufbcb\\ufbcb\\ufbcb\\ufbcb\"; print(uneval(s.match(r))); print(r.lastIndex);  } else { try { o0.v2 = evaluate(\"Object({}, x)\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (this.__defineGetter__(\"z\", decodeURI)), noScriptRval: x /= x, sourceIsLazy: 1.c = (4277), catchTermination: true })); } catch(e0) { } m1.has(e0); } });");
/*fuzzSeed-248247344*/count=12; tryItOut("mathy5 = (function(x, y) { return Math.pow((( - (Math.atan2(0x100000000, Math.fround(mathy3(Math.fround(x), ( + (x ** ((Math.atan2(y, (-0x0ffffffff | 0)) | 0) >>> 0)))))) | 0)) ? Math.fround(( ! Number.MAX_SAFE_INTEGER)) : ( + ( - ( + (y ? Math.fround(x) : y))))), Math.atanh((( + Math.log2(Math.fround(-(2**53+2)))) < ( ! Math.fround((((y >>> 0) << ((y ? y : Math.fround(( ! Math.fround(x)))) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-248247344*/count=13; tryItOut("print(x);");
/*fuzzSeed-248247344*/count=14; tryItOut("mathy0 = (function(x, y) { return (( ~ (Math.min((( + Math.hypot(( + (-0x080000001 << ( ! x))), ( + Math.hypot((Math.pow(y, y) >= ( ~ x)), Math.fround(( ~ Math.fround(((Number.MAX_VALUE >>> 0) === y)))))))) >>> 0), ( + Math.imul(((x ? y : ((Math.atanh(y) >>> 0) | 0)) ^ (y & Math.PI)), Math.expm1(Math.atan2(Math.atan2(x, y), (Math.ceil((y >>> 0)) >>> 0)))))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=15; tryItOut("h0.fix = f2;");
/*fuzzSeed-248247344*/count=16; tryItOut("mathy5 = (function(x, y) { return Math.asinh((mathy1(mathy4((( - (y + ( ! x))) === Math.atan2((1 >>> 0), x)), (((y + y) | 0) ? Math.pow(y, x) : Math.sqrt(x))), ( + (Math.atan2((((Math.exp(y) >>> 0) - (y >>> 0)) >>> 0), (Math.log(0x080000001) >>> 0)) | 0))) | 0)); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x0ffffffff, Math.PI, Number.MAX_VALUE, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, -(2**53), 0x080000001, -1/0, 0x100000001, -0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -0x100000001, 0/0, -0x080000000, -(2**53-2), -0x07fffffff, 0, 1, -(2**53+2), -0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 0x07fffffff, 2**53-2]); ");
/*fuzzSeed-248247344*/count=17; tryItOut("mathy3 = (function(x, y) { return Math.imul((((Math.fround(Math.min(Math.fround(( ! y)), Math.fround((( ! ( + (x && (y >>> 0)))) ^ ( + Math.hypot(y, (x | 0))))))) >>> 0) ? (( ! Math.log1p((( + (( + 0x100000001) >= ( + x))) * x))) >>> 0) : (( + Math.ceil(( + x))) >>> 0)) >>> 0), ( + ( + ( + Math.fround(Math.log2(Math.fround((mathy2(Math.sinh(Math.log1p(y)), Math.fround(((y ? (-0x100000000 - Math.fround(2**53-2)) : x) !== Math.asinh((x >>> 0))))) >>> 0)))))))); }); testMathyFunction(mathy3, [(new String('')), (new Number(-0)), '', [], ({valueOf:function(){return 0;}}), /0/, 1, (new Number(0)), false, (new Boolean(false)), NaN, '0', 0.1, undefined, null, objectEmulatingUndefined(), true, (new Boolean(true)), '/0/', 0, ({valueOf:function(){return '0';}}), (function(){return 0;}), [0], ({toString:function(){return '0';}}), '\\0', -0]); ");
/*fuzzSeed-248247344*/count=18; tryItOut("i2.next();");
/*fuzzSeed-248247344*/count=19; tryItOut("\"use strict\"; m1.get(h1);");
/*fuzzSeed-248247344*/count=20; tryItOut("\"use strict\"; let (x) { { void 0; void relazifyFunctions(); } }");
/*fuzzSeed-248247344*/count=21; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"new RegExp(\\\"$\\\", \\\"gyi\\\")\", ({ global: this.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 3 != 2), catchTermination: true }));m2.valueOf = (function() { a1.sort(g0, a0, f2, f2, t0); return p2; });\nt0 = t1.subarray(6);\n");
/*fuzzSeed-248247344*/count=22; tryItOut("mathy5 = (function(x, y) { return ( - (mathy0((new (new Function)([z1]) | 0), (Math.fround(Math.round(( - (y >= y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0x080000000, 0, Number.MAX_VALUE, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -0x100000000, 1, -0x080000000, Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, 1/0, 0x0ffffffff, 0x100000001, 0.000000000000001, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53+2), -0, 0x100000000, 0/0, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, 42, -(2**53-2), 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=23; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.pow(Math.fround(Math.ceil(( + Math.atan2(((((x | 0) % (x | 0)) << -0x100000000) , Math.pow(x, -(2**53))), ( + (Math.abs((y | 0)) | 0)))))), Math.imul((( ~ ( ! -0x100000001)) <= Math.fround(( ! y))), (((Number.MAX_VALUE >>> 0) <= ((( - ( - Math.tanh(y))) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 1/0, 0x100000000, Math.PI, 0x07fffffff, 0.000000000000001, 1, 1.7976931348623157e308, 2**53, 0, -0x080000001, Number.MAX_VALUE, 42, 2**53-2, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -0, -0x080000000, 0x080000001, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), -1/0, 2**53+2, 0x100000001, 0/0, -0x100000000]); ");
/*fuzzSeed-248247344*/count=24; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy2(mathy3(( + ( ~ (((y << Math.acos(y)) | 0) && ( - y)))), ( + (Math.min(x, Math.exp(x)) ^ 0))), ((( + Math.fround(( ~ Math.sin(y)))) | 0) ? (Math.asinh(Math.hypot(Math.min(y, -Number.MAX_VALUE), (mathy4(( + x), (Math.imul(( + x), -Number.MAX_VALUE) | 0)) >>> 0))) >>> 0) : ((Math.exp(( + x)) | 0) ? (Math.min(x, (-Number.MIN_VALUE >>> 0)) >>> 0) : Math.fround(( ~ (mathy0(y, (y >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-0x100000001, -1/0, 2**53+2, 0.000000000000001, -Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, 0x0ffffffff, 2**53-2, 0/0, 0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, -0, 0x100000001, 1/0, 2**53, 0x07fffffff, -0x100000000, 0x080000000, -0x080000001, 42, -(2**53), 1, 0, -(2**53-2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=25; tryItOut("\"use strict\"; b2 = new SharedArrayBuffer(36);");
/*fuzzSeed-248247344*/count=26; tryItOut("let tryekl, a = x, gddnef, nfzwks, ktuuft, x, qmiyxm, \u3056; /x/ ;");
/*fuzzSeed-248247344*/count=27; tryItOut("\"use strict\"; throw c;");
/*fuzzSeed-248247344*/count=28; tryItOut("\"use strict\"; M: for (let w of undefined) v1 = g1.eval(\"\\\"use strict\\\"; s2 = a1.join(s2);\");");
/*fuzzSeed-248247344*/count=29; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atanh((( ! ( + ( + Math.pow((Math.ceil(( + y)) >>> 0), ( + Math.fround(Math.round(Math.fround((Math.imul((x >>> 0), Math.fround(y)) >>> 0))))))))) >>> 0)) > (( + ( + ( + ( ~ (( ! Math.fround(( ~ (y ** x)))) | 0))))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[-0x080000000, true, -0x5a827999, function(){}, true, -0x5a827999, true, true, true, -0x080000000, -0x080000000, true, function(){}, function(){}, -0x080000000, true, -0x080000000, new Number(1.5), new Number(1.5), -0x080000000, -0x5a827999, -0x5a827999, function(){}, true, function(){}, true, -0x080000000, true, function(){}, new Number(1.5), -0x5a827999, new Number(1.5), -0x5a827999, -0x080000000, -0x080000000, -0x080000000, new Number(1.5), -0x080000000, -0x5a827999]); ");
/*fuzzSeed-248247344*/count=30; tryItOut("\"use strict\"; this.v0 = g1.a1.length;");
/*fuzzSeed-248247344*/count=31; tryItOut("g0.h0 = {};");
/*fuzzSeed-248247344*/count=32; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ (Math.expm1(-Number.MIN_SAFE_INTEGER) ? (Math.atan2(( + Math.fround(( - Math.fround((Math.fround(mathy2(Math.fround(y), Math.fround(x))) >= (x >>> 0)))))), ( + mathy0((y >>> 0), Math.fround((x ? (Math.max((y >>> 0), (y | 0)) | 0) : Math.fround(1/0)))))) >>> 0) : ( ~ ( ! -Number.MIN_SAFE_INTEGER)))); }); testMathyFunction(mathy3, [-0x07fffffff, 0/0, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, -0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), Number.MAX_VALUE, 1.7976931348623157e308, 1, 2**53, -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -(2**53), 0, -1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0.000000000000001, -(2**53+2), Number.MIN_VALUE, -0x080000001, -0x100000001, 0x100000000, 1/0, -Number.MIN_VALUE, 0x0ffffffff, -0x080000000, 0x080000000, 0x080000001, 2**53-2]); ");
/*fuzzSeed-248247344*/count=33; tryItOut("var NaN = x = window, a, [] = x, x, vexujo, z, x, eval, x;v0 = a2.length;");
/*fuzzSeed-248247344*/count=34; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 2305843009213694000.0;\n    var d4 = -2147483649.0;\n    var i5 = 0;\n    i2 = ((abs(((((i0) ? ((0x540cde05) == (0x19f20fc3)) : (i1))) >> ((i1)*-0x7c010)))|0) >= ((((0xd29f0b7a))) >> ((0x43ff8792) / (0xf73b10e9))));\n    return +((((+(-1.0/0.0))) - ((7.737125245533627e+25))));\n  }\n  return f; })(this, {ff: c =>  { return yield  /x/  } }, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x100000000, 0x080000000, Math.PI, 1.7976931348623157e308, -0x080000001, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, 2**53+2, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 0x07fffffff, 0x0ffffffff, 0x080000001, 1, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, -(2**53), 0, 1/0, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -1/0, -(2**53+2), 42, -0, 2**53, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-248247344*/count=35; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x080000001, -0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, -0, 42, 0/0, 2**53+2, Math.PI, -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 1, 0x0ffffffff, 0x07fffffff, 0, -(2**53-2), 0.000000000000001, -0x07fffffff, 0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -(2**53), -0x100000000, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 2**53, 0x100000001]); ");
/*fuzzSeed-248247344*/count=36; tryItOut(";");
/*fuzzSeed-248247344*/count=37; tryItOut("Array.prototype.unshift.apply(g2.a0, [false]);");
/*fuzzSeed-248247344*/count=38; tryItOut("v2 + i1;");
/*fuzzSeed-248247344*/count=39; tryItOut("mathy3 = (function(x, y) { return ( - ( - ( + Math.clz32(( + ( + (y < ((((( + Math.sinh(( + x))) , x) | 0) * (x | 0)) | 0)))))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 0.000000000000001, -0x100000001, 0x07fffffff, -0, 0, -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -0x100000000, -(2**53), 2**53, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), -0x0ffffffff, -(2**53+2), 0x100000001, 0x100000000, 1, 0x080000000, 0x080000001, Math.PI, 42, 0/0, Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-248247344*/count=40; tryItOut("\"use strict\"; v1 = t0.byteOffset\nthis.f2 = x;");
/*fuzzSeed-248247344*/count=41; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - (Math.acosh(y) - Math.tanh((((( ! ((Math.atanh(((( - (2**53-2 | 0)) | 0) | 0)) | 0) | 0)) | 0) >>> 0) ^ (( + (x ^ y)) >>> 0))))); }); ");
/*fuzzSeed-248247344*/count=42; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 274877906945.0;\n    {\n;    }\n    (Float32ArrayView[2]) = ((+/*FFI*/ff(((((i1)+(i1)-((imul((i1), (i0))|0))) ^ ((!(i1))-(0xfb61effe)+(0xabb38eb5)))), ((~((i0)+(i1)-((((0x2e57e2b8)-(0xa357ac59)-(0xbd00a564))>>>(-((0x45b8e22b)))))))), ((((i1)*-0x32c3f) >> ((i1)))), ((imul(((-524288.0) >= (+(((0x79a073cb))>>>((0xc3285035))))), ((((0xffffffff)-(-0x8000000)-(0xfe53a902))>>>((0x63c574e4)+(0xfe9055f3)))))|0)), (((((0x6867918f))) | ((Uint16ArrayView[((0xf8cc80da)-(0xc81f8480)) >> 1])))), ((((0xf475f274)*-0xfffff) << ((i1)+(i1)))), ((-0.5)), ((9007199254740992.0)), ((33554431.0)))));\n    return (((i1)-((1.2089258196146292e+24) <= (-1.0078125))+((0xffffffff))))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, 0x0ffffffff, 0x100000000, 2**53+2, 0.000000000000001, 0x080000000, 0x07fffffff, Number.MAX_VALUE, 2**53-2, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, 1.7976931348623157e308, -0x07fffffff, 0, -(2**53), -1/0, 0x080000001, 1, -Number.MAX_VALUE, -0, 42, -Number.MIN_VALUE, -(2**53-2), 0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=43; tryItOut("M:with((eval = (4277)))/*MXX1*/o0 = g2.Promise.prototype.catch;\nfor(var y = false in -14) [[]];\n");
/*fuzzSeed-248247344*/count=44; tryItOut("/*RXUB*/var r = r0; var s = \u0009.valueOf(\"number\") || x[/*\n*/\"__count__\"] = let (c) ((void shapeOf(-13))).valueOf(\"number\").yoyo(x > \nx); print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=45; tryItOut("mathy4 = (function(x, y) { return (((Math.fround((Math.pow(mathy1(Math.max(/*RXUE*//(?:.(?!\\B))*/gm.exec(\"\"), Math.clz32(y)), x), (x | 0)) >>> 0)) | 0) | 0) === mathy0(( ~ (x >>> 0)), mathy0(y, (Math.fround(x) * x)))); }); testMathyFunction(mathy4, [-0x100000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, 0x100000001, -0, -Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 0/0, 2**53+2, -(2**53-2), 0, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, Math.PI, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -(2**53+2), 0x0ffffffff, -(2**53), -0x080000000, 1, Number.MIN_VALUE, -0x100000000, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-248247344*/count=46; tryItOut("g1.__proto__ = v2;");
/*fuzzSeed-248247344*/count=47; tryItOut("a1.shift((\u3056) >> Function.prototype, h1);function z( , ...x) { a0[12]; } var cxrdnm = new ArrayBuffer(4); var cxrdnm_0 = new Uint32Array(cxrdnm); cxrdnm_0[0] = -2; var cxrdnm_1 = new Float64Array(cxrdnm); cxrdnm_1[0] = -0.807; var cxrdnm_2 = new Int8Array(cxrdnm); print(cxrdnm_2[0]); cxrdnm_2[0] = -18; var cxrdnm_3 = new Uint8ClampedArray(cxrdnm); cxrdnm_3[0] = 20; var cxrdnm_4 = new Float64Array(cxrdnm); var cxrdnm_5 = new Uint16Array(cxrdnm); cxrdnm_5[0] = -9; var cxrdnm_6 = new Int8Array(cxrdnm); cxrdnm_6[0] = -1409452923; /*MXX3*/g2.o2.g2.Math.fround = g2.Math.fround;x => \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0x4795b815);\n    i1 = (0xfc419b18);\n    {\n      {\n        i1 = (0x46baf383);\n      }\n    }\n    return (((i1)+((~(((d0) != (+abs(((Infinity)))))+((((((runOffThreadScript).apply)((new (\"\\u6FF3\")( '' , [z1]))))) >> ((0x542e7d3f) / (0x4fd8dc51))) >= (~~(8193.0))))))))|0;\n  }\n  return f;a0.shift();print(allocationMarker());a0 = arguments;v1 + '';");
/*fuzzSeed-248247344*/count=48; tryItOut("\"use strict\"; g1.v0 = Object.prototype.isPrototypeOf.call(b1, o0);");
/*fuzzSeed-248247344*/count=49; tryItOut("b0 + '';");
/*fuzzSeed-248247344*/count=50; tryItOut("mathy2 = (function(x, y) { return Math.hypot((((Math.fround(Math.cbrt(((( + ((Math.min((Math.fround(( - Math.fround(-0x080000001))) | 0), (y | 0)) ? Math.fround(Math.pow(( + (( + x) >> ( + 0x07fffffff))), y)) : x) | 0)) !== x) | 0))) | 0) && (((((Math.cos((Math.PI >>> 0)) >>> 0) | 0) != ( + (( + 0x080000001) + ( + ( + (( + (Math.abs(x) | 0)) !== ( + (Math.asinh((y >>> 0)) >>> 0)))))))) >>> 0) >>> 0)) | 0), (( ~ Math.cos(( - (Math.min(x, Math.fround((Math.pow((x >>> 0), (Math.asin((0x100000000 >>> 0)) >>> 0)) >>> 0))) | 0)))) >>> 0)); }); testMathyFunction(mathy2, [-0x080000001, 0x0ffffffff, -0, 1, -Number.MIN_SAFE_INTEGER, 0/0, Math.PI, -Number.MIN_VALUE, -(2**53-2), 42, -0x0ffffffff, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0, -(2**53), Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 0x080000000, 0.000000000000001, -Number.MAX_VALUE, -0x100000000, 0x100000001, 0x07fffffff, 0x080000001, 2**53-2]); ");
/*fuzzSeed-248247344*/count=51; tryItOut("\"use strict\"; for (var v of m2) { try { m1.set(m0, s1); } catch(e0) { } try { for (var p in h1) { try { v2 = (g1.t2 instanceof m2); } catch(e0) { } try { g0.__proto__ = t1; } catch(e1) { } try { /*ADP-2*/Object.defineProperty(o2.a1, 15, { configurable: false, enumerable: (x % 5 == 3), get: (function() { try { f1.toString = f2; } catch(e0) { } i0 = new Iterator(s2); return e1; }), set: f0 }); } catch(e2) { } print(this.t1); } } catch(e1) { } m0.set(b2, i2); }function w()\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1.03125;\n    var i3 = 0;\n    return +((d2));\n  }\n  return f;L:if(true) { if (Math.min((this.__defineGetter__(\"z\", new Function)), eval(\"v2 = evaluate(\\\"/* no regression tests found */\\\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: undefined, noScriptRval: (x % 18 != 8), sourceIsLazy: false, catchTermination: (x % 4 == 0) }));\",  /x/g ))) this.o1.v0.toSource = f2;} else /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { print(x);return 12; }}), { configurable: new RegExp(\"\\u9187+?\", \"m\"), enumerable: (x % 14 != 12), get: (function() { try { /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { v2 = t0.length;return 12; }}), { configurable: false, enumerable: true, get: String.fromCodePoint, set: (function(j) { if (j) { try { for (var p in p0) { try { i0.next(); } catch(e0) { } try { for (var v of g2) { try { Object.prototype.watch.call(s0, \"setUTCDate\", (function() { for (var j=0;j<2;++j) { f2(j%2==0); } })); } catch(e0) { } o1.t0.__proto__ = a2; } } catch(e1) { } i2 = e0.entries; } } catch(e0) { } try { m1.get(s1); } catch(e1) { } print(uneval(v2)); } else { print(t2); } }) }); } catch(e0) { } try { g0.__proto__ = a1; } catch(e1) { } try { h0 + ''; } catch(e2) { } Array.prototype.reverse.call(a1); return a1; }), set: f2 });");
/*fuzzSeed-248247344*/count=52; tryItOut("true;( '' );");
/*fuzzSeed-248247344*/count=53; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=54; tryItOut("zljvtr();/*hhh*/function zljvtr(){print(x);}");
/*fuzzSeed-248247344*/count=55; tryItOut("\"use strict\"; a1 + o1;");
/*fuzzSeed-248247344*/count=56; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( - Math.hypot((Math.hypot(Math.cosh(y), 0x100000001) ? ( + Math.cbrt(( + (Math.log(((x ? y : x) | 0)) | 0)))) : Math.max(( ! x), Math.asin(x))), Math.tanh(((( ! y) | 0) <= y)))); }); testMathyFunction(mathy0, /*MARR*/[-Number.MAX_VALUE, false, false, -Number.MAX_VALUE, -Number.MAX_VALUE, false, -Number.MAX_VALUE, false, false, false, false, false, -Number.MAX_VALUE, -Number.MAX_VALUE, false, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, false, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, false, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=57; tryItOut("\"use strict\"; qjblrt((d));/*hhh*/function qjblrt(a, a){switch('fafafa'.replace(/a/g, Array.prototype.shift)) { case (void shapeOf(delete b.a)): case (makeFinalizeObserver('tenured')): g1.v1 = (v0 instanceof o1.i2);break;  }}");
/*fuzzSeed-248247344*/count=58; tryItOut("let v2 = evaluate(\"function f1(h2) (void options('strict_mode'))\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (4277), noScriptRval: false, sourceIsLazy: eval = y = Proxy.create(({/*TOODEEP*/})( \"\" ), null).__defineSetter__(\"{}\", ((/*wrap2*/(function(){ \"use strict\"; var ruiqti = {}; var obaekm = decodeURI; return obaekm;})()).call(\"\\uE127\".hypot([,], /(\\2)(?!\\1*)|(?:\\D)|\uc284{4,8}|(.|\\d?^[^]|\\f)*?/ym), Math.pow(true, new RegExp(\"\\\\B\", \"gm\")))).apply), catchTermination: true }));");
/*fuzzSeed-248247344*/count=59; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan2(((( + Math.fround(( + Math.fround(( + Math.atan((( - Number.MAX_SAFE_INTEGER) << y))))))) + ( + (( ! -Number.MIN_SAFE_INTEGER) | 0))) | 0), ((Math.atan2((Math.sin(( + ( ! ( + x)))) && x), (Math.fround(( + Math.fround(( ! (Math.asinh(x) >>> 0))))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [0, -1/0, 1.7976931348623157e308, 0/0, 0x080000001, -(2**53), 1, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 2**53, Number.MAX_VALUE, 0.000000000000001, 2**53+2, 1/0, 0x100000000, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, 0x0ffffffff, -0, Math.PI, Number.MIN_VALUE, 2**53-2, -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 0x080000000, -0x100000000, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=60; tryItOut("a2 = [];/*RXUB*/var r = x; var s = \"\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-248247344*/count=61; tryItOut("4095;");
/*fuzzSeed-248247344*/count=62; tryItOut("mathy3 = (function(x, y) { return Math.ceil(( ! Math.imul(( + Math.max((y !== x), Math.cos(y))), ( + 1/0)))); }); ");
/*fuzzSeed-248247344*/count=63; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((((i1)-(0x72d7cc02)-((x ? z : new (false)(this)))) ^ ((0xeb0c5787))));\n    i1 = ((0x0) >= (0x89dc3ab));\n    i1 = (((((i1)) & ((0x5c30873d))) < (imul((i1), ((((-0x8000000)) >> ((0xda6ac3e0)))))|0)) ? (i1) : (i1));\n    return (((0xfac8ba32)+(0xfe632c72)+(0x95697ee9)))|0;\n  }\n  return f; })(this, {ff: (ArrayBuffer).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[NaN = 20, (-1/0), (-1/0), arguments.callee, arguments.callee, (-1/0), {}, arguments.callee, NaN = 20, {}, (-1/0), {}, {}, NaN = 20, NaN = 20, {}, (-1/0), {}, {}, {}, NaN = 20, {}, {}, {}, {}, arguments.callee, {}, {}, NaN = 20, NaN = 20, arguments.callee, {}, NaN = 20, {}, {}, arguments.callee, (-1/0), NaN = 20, {}, {}, {}, {}, (-1/0), NaN = 20, {}, (-1/0), NaN = 20, {}, arguments.callee, arguments.callee, {}, (-1/0), {}, arguments.callee, arguments.callee, arguments.callee, {}, {}, {}, {}, {}, {}, arguments.callee, NaN = 20, {}, {}, (-1/0), (-1/0), arguments.callee, {}, {}, arguments.callee, arguments.callee, {}, (-1/0), NaN = 20, (-1/0), NaN = 20, {}, {}, {}, {}, NaN = 20, {}, arguments.callee, arguments.callee, {}, (-1/0), NaN = 20, {}, {}, {}, {}, (-1/0), NaN = 20, arguments.callee, NaN = 20, {}, {}, (-1/0), {}, {}, {}, (-1/0), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, (-1/0), arguments.callee, NaN = 20, {}, arguments.callee, {}, arguments.callee, {}, arguments.callee, {}, (-1/0), {}, {}, {}, NaN = 20, {}, {}, {}, {}, {}, {}, {}, {}, arguments.callee, (-1/0)]); ");
/*fuzzSeed-248247344*/count=64; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (mathy0((Math.atan2((-0x100000000 | 0), (Math.fround(mathy0(Math.fround(( ! ( + Math.sign(y)))), Math.fround(y))) | 0)) | 0), Math.max((( + (y >>> 0)) >>> 0), (y <= ( ! ( ! ( + y)))))) << Math.sin((((( + y) >>> 0) >>> 0) + y))); }); ");
/*fuzzSeed-248247344*/count=65; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=66; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.asin(((( + y) | (Math.atan2(Math.PI, (Math.min(( - y), Math.fround(1.7976931348623157e308)) | 0)) | 0)) | 0))), Math.fround((Math.asinh(Math.sqrt(x)) | 0)))); }); testMathyFunction(mathy3, [(new Boolean(false)), false, undefined, ({valueOf:function(){return '0';}}), (new Number(-0)), '/0/', 0.1, (new String('')), NaN, /0/, null, ({toString:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(true)), [], (function(){return 0;}), (new Number(0)), -0, true, '\\0', 1, '', '0', ({valueOf:function(){return 0;}}), 0, [0]]); ");
/*fuzzSeed-248247344*/count=67; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.tan((( + ( - ( + (Math.hypot(Math.atan2((x != Math.PI), x), 2**53) >>> Math.max(Math.exp(0x0ffffffff), (Math.tan((Math.max(Math.fround(y), x) | 0)) | 0)))))) | 0)); }); ");
/*fuzzSeed-248247344*/count=68; tryItOut("\"use strict\"; a1.unshift(p1, h2, o1, h2);");
/*fuzzSeed-248247344*/count=69; tryItOut("\"use strict\"; for (var v of e0) { try { i2 = new Iterator(i2); } catch(e0) { } try { this.o0 + ''; } catch(e1) { } /*RXUB*/var r = r2; var s = this.s0; print(s.match(r));  }");
/*fuzzSeed-248247344*/count=70; tryItOut("v0 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-248247344*/count=71; tryItOut("testMathyFunction(mathy5, [-(2**53+2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, 2**53, 0x0ffffffff, -0x100000000, 0/0, -Number.MIN_VALUE, 0, -1/0, -(2**53-2), Number.MAX_VALUE, -0x080000001, -(2**53), 0x100000000, -0x080000000, -0, 2**53+2, 1.7976931348623157e308, 1/0, -0x100000001, 0x080000000, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=72; tryItOut("print(x)");
/*fuzzSeed-248247344*/count=73; tryItOut("mathy5 = (function(x, y) { return ((Math.acosh(Math.fround(Math.max(Math.fround(Math.acos(y)), ( + (y ? x : (-0x100000000 | 0)))))) | 0) >>> ( + Math.abs((( + ( ~ ( - -0x100000001))) >>> 0)))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 1, -0x080000000, -0x07fffffff, 0/0, 0x100000000, -0x100000001, 0.000000000000001, Number.MAX_VALUE, 0x080000001, -0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, 0, -0, -Number.MIN_VALUE, 42, 0x080000000, 0x07fffffff, Number.MIN_VALUE, 2**53+2, -0x0ffffffff, Math.PI, -(2**53+2), 2**53, -0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53-2), 2**53-2]); ");
/*fuzzSeed-248247344*/count=74; tryItOut("g2.m0.set(f1, a1);");
/*fuzzSeed-248247344*/count=75; tryItOut("\"use strict\"; v1 = evalcx(\"f2(this.s2);\", g0);");
/*fuzzSeed-248247344*/count=76; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?=$)|(?:(?=\\\\d))+?(?=[^\\\\cN\\\\f]){4,}|(?=[^])){3,6}(?=(?![^\\u4723-\\\\\\u9ec4\\\\xfC-\\ua57b]\\\\1|$\\\\D?(^)?[^][\\uc444\\\\x6a]|\\\\w+))\", \"gim\"); var s = x; print(s.search(r)); ");
/*fuzzSeed-248247344*/count=77; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.tan(Math.fround(( - Math.fround(Math.trunc(x))))); }); testMathyFunction(mathy3, [2**53, -(2**53), 0x080000000, 0x07fffffff, 1/0, -0, -Number.MIN_VALUE, 1, -0x100000000, -0x080000001, 1.7976931348623157e308, 0x100000000, 0x0ffffffff, 0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, 42, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0.000000000000001, 0, Number.MIN_VALUE, -1/0, -0x0ffffffff, -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=78; tryItOut("\"use strict\"; o0 + e1;");
/*fuzzSeed-248247344*/count=79; tryItOut("mathy0 = (function(x, y) { return Math.hypot((((Math.pow(Math.fround(Math.hypot(Math.fround((Math.imul((y | 0), (y | 0)) | 0)), Math.fround(y))), Math.fround(( + ( + (( ! y) >>> 0))))) | 0) + (( - Math.log1p(y)) | 0)) | 0), ( + ((Math.min((Math.fround(Math.pow((Math.log1p(((Math.imul(((((x >>> 0) + (y >>> 0)) >>> 0) | 0), ( + y)) | 0) >>> 0)) >>> 0), (Math.imul((y >>> 0), y) >>> 0))) | 0), (y | 0)) | 0) ^ ( + (( ~ (( - Math.fround(((x | 0) >= -Number.MAX_SAFE_INTEGER))) | 0)) | 0))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -(2**53-2), Number.MAX_VALUE, 0x100000001, -0x100000000, -(2**53+2), -0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, 1, -1/0, 0/0, Math.PI, 42, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000001, 0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, 0x07fffffff, -(2**53), 0x0ffffffff, -Number.MIN_VALUE, 0, -0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, 2**53, 0x100000000, 0x080000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=80; tryItOut("\"use strict\"; let ({window, \u3056: {x: a, x: NaN, x: {c: {e, c: x, NaN: {NaN: [{x: {c: []}, x: {x}, z: [[]]}, x, , x]}, (window), x: x}, NaN: arguments.callee.arguments, NaN: {c: -13.unwatch(\"1\").__proto__}, \u3056}, b: [\u3056], y: {c: {\u3056: [, [[], [], NaN([ /* Comment */ /x/ ]), [, [{}]]]], e: y, x, x: null}}}} = 21, NaN) { m0.delete(b2); }");
/*fuzzSeed-248247344*/count=81; tryItOut("\"use strict\"; testMathyFunction(mathy2, [[0], false, '0', ({valueOf:function(){return '0';}}), (function(){return 0;}), undefined, '/0/', (new Number(-0)), '', objectEmulatingUndefined(), 1, '\\0', 0, (new String('')), null, /0/, (new Boolean(true)), 0.1, ({toString:function(){return '0';}}), true, (new Number(0)), (new Boolean(false)), NaN, [], -0, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-248247344*/count=82; tryItOut("mathy3 = (function(x, y) { return ((( + mathy2(( + Math.fround((Math.fround(Math.atan2(-0x080000001, ( ~ Number.MAX_VALUE))) ^ Math.fround((y ? x : Math.imul(mathy1(x, Math.asinh(x)), x)))))), ( + ( - (Math.min(((Math.atan2((y | 0), (( - Math.fround(y)) | 0)) | 0) >>> 0), (Math.round(y) >>> 0)) | 0))))) >> ((Math.imul((0 >>> 0), ( + Math.max(Math.fround(y), Math.fround(y)))) >>> 0) ? Math.atan2(Math.fround(Math.trunc(Math.fround(( + Number.MIN_VALUE)))), Math.clz32(( + (Math.fround(x) / Math.imul(y, y))))) : ( - Math.imul((Math.imul(y, -(2**53-2)) | 0), y)))) | 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 1/0, 1, -0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), -1/0, 0x080000000, 2**53+2, 0, 42, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -(2**53+2), 2**53-2, 0x080000001, 2**53, 0x100000000, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -0x100000000, -0x100000001, -(2**53-2), 0x100000001, 0x07fffffff, -0]); ");
/*fuzzSeed-248247344*/count=83; tryItOut("testMathyFunction(mathy0, [NaN, ({valueOf:function(){return 0;}}), (new Boolean(true)), /0/, (new Number(0)), (function(){return 0;}), (new String('')), null, objectEmulatingUndefined(), (new Number(-0)), undefined, '\\0', ({valueOf:function(){return '0';}}), -0, 0.1, '/0/', true, [], 0, (new Boolean(false)), false, '0', ({toString:function(){return '0';}}), '', [0], 1]); ");
/*fuzzSeed-248247344*/count=84; tryItOut("t2 = x;");
/*fuzzSeed-248247344*/count=85; tryItOut("v0 = r0.compile;\nm0.set(o0.f1, -14);print(x);\n");
/*fuzzSeed-248247344*/count=86; tryItOut("mathy5 = (function(x, y) { return Math.ceil(mathy1(Math.atan2((((x >>> 0) / ((x + (((0x080000001 >>> 0) >>> (x >>> 0)) >>> 0)) >>> 0)) >>> 0), (((y >>> 0) ? ( + y) : x) , Math.log2(( ~ (0x080000001 ? Number.MAX_VALUE : 0/0))))), Math.atan2(( + Math.sinh(( + Math.fround(Math.log1p(( + (( ~ (y >>> 0)) | 0))))))), (Math.fround(( - ((x ? x : x) | 0))) ? x : Math.fround(Math.min(Math.fround((mathy1(x, y) | 0)), Math.fround((42 ? Math.pow(y, ( + y)) : -0x100000001)))))))); }); ");
/*fuzzSeed-248247344*/count=87; tryItOut("\"use strict\"; /*infloop*/for(var b = x; y\u0009 = this ? (new Array( /x/g ,  \"\" )) : a = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"((?=\\\\S))\", \"y\")), function (x = window, x, z =  /x/ , eval, x, z, x, w, x = /\\W*/gm, eval, x, eval, b, eval, NaN, z, \u3056, x, w, \u3056, c = -8, x,  , y, NaN, x, w = true, x, a, x, x, c, a, x, x, c, e, window, x =  /x/ , x, function ([y]) { }, x, x = b, b, NaN = null, d, y, x, x, e, e, \u3056, x, c = \"\\uC25E\", NaN, x, y, z, eval = [[]], x = 28, w, this.window, x, window, x, x = null, e =  /x/ , x, eval, e, c, x, z, w, this.a,  , x, 26 = false, w, \u3056, window, d, d, \u3056, x, x, b =  /x/ , x = \"\\u9D3A\", ...x) { yield  /x/  } ).watch(\"codePointAt\", decodeURI); ({ get valueOf   (a)\"use asm\";   var Infinity = stdlib.Infinity;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    d0 = (+(1.0/0.0));\n    d0 = (Infinity);\n    return (((i1)))|0;\n  }\n  return f; })) {if(false) print(x); }");
/*fuzzSeed-248247344*/count=88; tryItOut("L:if(false) { if ((yield x)) {o2.i2.next(); }} else v2 = evalcx(\" /x/ \", g2);");
/*fuzzSeed-248247344*/count=89; tryItOut("mathy5 = (function(x, y) { return (mathy3((( ! (-0x0ffffffff | 0)) | 0), Math.fround(Math.hypot(Math.fround((Math.abs(((Math.clz32((( ~ Math.exp(1.7976931348623157e308)) >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.fround((Math.max(0.000000000000001, -0x080000000) >>> x))))) !== ( + (Math.trunc(( + ((0x080000001 >>> 0) ? (y >>> 0) : ( ~ 1)))) >>> 0))); }); testMathyFunction(mathy5, [-0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0/0, 2**53+2, Number.MIN_VALUE, -0x080000000, 0x080000001, 1/0, -Number.MAX_VALUE, -0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 1, 0x07fffffff, 0x0ffffffff, -(2**53-2), 42, 0, -(2**53+2), -(2**53), -1/0, 0x100000000, 2**53-2, -0x100000001, 0.000000000000001, Number.MAX_VALUE, 2**53, 0x100000001, Math.PI, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=90; tryItOut("print(uneval(t2));");
/*fuzzSeed-248247344*/count=91; tryItOut("b2 + g0.g1.p0;");
/*fuzzSeed-248247344*/count=92; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var exp = stdlib.Math.exp;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    {\n      i1 = ((0xbb717553));\n    }\nh1.has = (function(j) { if (j) { s1 = s0.charAt(v1); } else { try { e0.valueOf = (function() { try { h1 + ''; } catch(e0) { } Array.prototype.forEach.call(a0, f1, g2.m0, p0); return this.p1; }); } catch(e0) { } try { v0 = this.r1.global; } catch(e1) { } try { t0.set(this.a0, ({valueOf: function() { Object.defineProperty(this, \"v2\", { configurable: (x % 72 != 24), enumerable: true,  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: false })); } });return 17; }})); } catch(e2) { } t2 = x; } });    i0 = (i0);\n    i0 = (i1);\n    i0 = ((((i1)) & ((((('fafafa'.replace(/a/g, (WebAssemblyMemoryMode).call))(\"\\u37A3\" == \u3056))))-(i1))));\n    return +(this.__defineSetter__(\"\\u3056\",  \"\"  && new RegExp(\".|(?=\\\\s)*?{1073741824,}(?!.?\\ub792{2,5})+\", \"m\")));\n    switch ((~~(+sqrt((this))))) {\n      case -2:\n        {\n          i0 = (i0);\n        }\n        break;\n      case -2:\n        ( /x/g .prototype) = ((i0)-(!(i1)));\n        break;\n      case -3:\n        (Int8ArrayView[2]) = ((Uint8ArrayView[(((~~(+abs(((Float32ArrayView[((i0)*0xfffff) >> 2]))))))) >> 0]));\n        break;\n      case 1:\n        i1 = (i0);\n      case 0:\n        return +((Float32ArrayView[((i0)+(((+abs(((+/*FFI*/ff()))))))) >> 2]));\n        break;\n    }\n    i1 = (i0);\n    (Uint32ArrayView[2]) = ((0xa627c7d5)+(i1));\n    i1 = ((0x0) >= (0x89461790));\n    {\n      (Int8ArrayView[2]) = ((((i0))>>>(((0xffffffff))*-0x807f9)) / (0x34a5fb76));\n    }\n    /*FFI*/ff(((+exp(((+/*FFI*/ff((((((~~(((1.001953125)) - ((-1.5474250491067253e+26)))))) | ((i0)))), ((imul((i0), (i0))|0)), ((0x4c8f68c4)), (((4.722366482869645e+21) + (-140737488355329.0))), ((((1048577.0)) * ((-131071.0)))), ((-288230376151711740.0)), ((-65.0)))))))), ((abs((imul((0x945e8db1), (/*FFI*/ff(((imul((0x2fb6b460), (0x9aa52b5c))|0)), ((-((576460752303423500.0)))))|0))|0))|0)), ((-0.00390625)), ((/[^\\u001a--\\S]/gyim)));\n    {\n      i1 = (i0);\n    }\n    i1 = ((Int32Array--) ? (!(i0)) : (i1));\n    i1 = (i1);\n    return +(x);\n  }\n  return f; })(this, {ff: Proxy}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x080000000, 2**53+2, Number.MAX_VALUE, 42, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, -0x0ffffffff, -(2**53-2), 0x100000001, -0x100000000, Math.PI, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 2**53-2, 0, 0x100000000, Number.MIN_VALUE, 0x080000000, -0, 0/0, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, 1, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=93; tryItOut("\"use strict\"; { void 0; deterministicgc(true); }");
/*fuzzSeed-248247344*/count=94; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.pow((Math.hypot(( + Math.pow(( + Math.pow((Math.acos(Math.fround(Math.cosh(x))) >>> 0), ( + Math.fround((Math.fround((mathy0((y >>> 0), (x >>> 0)) >>> 0)) === Math.fround(y)))))), (x | 0))), mathy0(y, Math.asinh(y))) * Math.fround((Math.pow(-4, /*MARR*/[2**53-2, 2**53-2, 2**53-2, y, 2**53-2, y, y, y, y, y, y, y, 2**53-2, y, y, y, 2**53-2, 2**53-2, y, 2**53-2, 2**53-2, y, y, y, 2**53-2, y, y, y, y, y, y, y, 2**53-2, y, y, y, 2**53-2, y, 2**53-2, 2**53-2, 2**53-2, 2**53-2, y, 2**53-2, 2**53-2, y, y, y, y, 2**53-2, y, 2**53-2, y, 2**53-2, y, 2**53-2, y, y, 2**53-2, y, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, y, y, y, y, y, y, y, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, y, 2**53-2, 2**53-2, 2**53-2].some(offThreadCompileScript,  /x/ ))))), ((mathy0(Math.sqrt(( + Math.hypot(Math.tan(( + mathy0(0.000000000000001, ( + y)))), (x << y)))), ( + (( + y) > ( + (x + -0))))) >>> 0) | 0)); }); ");
/*fuzzSeed-248247344*/count=95; tryItOut("\"use strict\"; let (c = x >= a, udmncn, x, x, ({/*TOODEEP*/})(Math), x, xqeooo, pwgfaa, x) { o1.i1.send(s1); }");
/*fuzzSeed-248247344*/count=96; tryItOut("/*tLoop*/for (let d of /*MARR*/[]) { v2 = g2.runOffThreadScript(); }");
/*fuzzSeed-248247344*/count=97; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + Math.tan((( ! x) | 0))) >>> ( ~ (Math.max((Math.ceil(Math.fround((Math.fround(y) % Math.fround(y)))) >>> 0), (Math.fround(( + Math.fround(( + Math.log2((x >>> 0)))))) >>> 0)) | 0)))); }); testMathyFunction(mathy4, [undefined, (new Boolean(true)), 0.1, '\\0', 0, ({valueOf:function(){return 0;}}), /0/, (new Number(-0)), '0', 1, (new Boolean(false)), (new String('')), -0, [], [0], false, true, '', objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new Number(0)), (function(){return 0;}), NaN, ({valueOf:function(){return '0';}}), '/0/', null]); ");
/*fuzzSeed-248247344*/count=98; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - Math.atan2((Math.exp(Math.fround(Math.fround(Math.ceil((( ! (y >>> y)) >>> 0))))) >>> 0), (Math.acos(((((x >>> 0) | ((Math.max(((mathy0(0x080000000, x) >>> 0) | 0), ( - -Number.MAX_VALUE)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [0x100000001, -Number.MIN_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), Math.PI, 1/0, 0/0, -(2**53-2), -0x080000000, -(2**53), -0x07fffffff, 2**53+2, 0x07fffffff, -0x100000000, 0x0ffffffff, 2**53, 0.000000000000001, -1/0, Number.MAX_VALUE, 1, -0x100000001, 0x080000001, 2**53-2]); ");
/*fuzzSeed-248247344*/count=99; tryItOut("s2 = s2.charAt(/*RXUE*//\\3/yim.exec(\"\\uf806\"));");
/*fuzzSeed-248247344*/count=100; tryItOut("s2 = '';");
/*fuzzSeed-248247344*/count=101; tryItOut("testMathyFunction(mathy1, [2**53+2, 2**53, -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), Number.MAX_VALUE, -1/0, Math.PI, -Number.MAX_VALUE, -(2**53), 0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -(2**53-2), 1, 0x100000001, -0x080000000, 1/0, Number.MIN_VALUE, 0x100000000, 0x07fffffff, 42, 0.000000000000001, 0/0, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-248247344*/count=102; tryItOut("function ([y]) { };print(\"\\u92E3\");m0.get(g2.i0);");
/*fuzzSeed-248247344*/count=103; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! Math.fround(Math.sinh((Math.fround(Math.ceil((((Math.pow(( + Math.min((( + y) >>> 0), ( + Math.abs(x)))), 0x080000000) ? Math.imul(( + Math.max(x, x)), ( + -0x100000000)) : ((Math.acosh(((Math.sign((y >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0))) | 0)))); }); ");
/*fuzzSeed-248247344*/count=104; tryItOut("mathy5 = (function(x, y) { return mathy4((Math.asin((Math.min((( + (x ? (y | 0) : (y | 0))) ^ 0.000000000000001), x) >>> 0)) | 0), (( + ( ! ( + ( + Math.tan((Math.tan(y) >>> 0)))))) ? ( - mathy3(((Math.cos((1/0 | 0)) | 0) >>> 0), ((x , (Number.MAX_VALUE ? ( ~ x) : 2**53-2)) >>> 0))) : Math.pow((( + ((y & x) >>> 0)) >>> 0), ( + ( - ( + y)))))); }); testMathyFunction(mathy5, [Math.PI, 0x080000000, 1.7976931348623157e308, 0x100000001, 42, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), -0x100000001, 0x07fffffff, 0x080000001, -0x080000000, -0x100000000, -0x0ffffffff, -0x07fffffff, 1, -0, Number.MAX_VALUE, 0/0, -1/0, -Number.MIN_VALUE, 0, 1/0, Number.MIN_VALUE, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53, -(2**53)]); ");
/*fuzzSeed-248247344*/count=105; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((((Math.hypot(Math.fround(( ! (( + ( + ( + y))) ^ y))), Math.fround((Math.tanh((Math.atan2(0, y) | 0)) | 0))) | 0) === Math.fround((( ! (Math.atan2((Math.asin(Math.fround(( + mathy0(Math.min(y, y), ( + x))))) | 0), Math.fround(Math.acos(Math.fround((x ? y : y))))) >>> 0)) >>> 0))) >>> 0) ? Math.acos((Math.cos(0) | 0)) : Math.fround(Math.asinh(Math.fround((mathy2(x, (x ? Math.sinh(Math.fround((y >= Math.fround(x)))) : (( ! x) >>> 0))) | 0))))); }); testMathyFunction(mathy5, [({valueOf:function(){return 0;}}), true, 0, false, 1, '\\0', null, /0/, '0', (function(){return 0;}), '', '/0/', undefined, objectEmulatingUndefined(), 0.1, ({toString:function(){return '0';}}), (new Boolean(false)), [], (new Number(0)), -0, ({valueOf:function(){return '0';}}), [0], (new Number(-0)), (new Boolean(true)), (new String('')), NaN]); ");
/*fuzzSeed-248247344*/count=106; tryItOut("/*tLoop*/for (let x of /*MARR*/[x, new Boolean(false), new Boolean(false), x, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, new Boolean(false), false, x, new Boolean(false), x, x, false, x, new Boolean(false), new Boolean(false), x, x, x, x, false, x, false, new Boolean(false), new Boolean(false), false, false, x, new Boolean(false), false, false, new Boolean(false), new Boolean(false), x, x, new Boolean(false), new Boolean(false), x, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), false, x, x, x, x, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, x, x, false, x, new Boolean(false), new Boolean(false), x, false, new Boolean(false), false, new Boolean(false), false, new Boolean(false), x, new Boolean(false), new Boolean(false), false, x, x, false, x, x, false, new Boolean(false), false, x, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), x, new Boolean(false), x, x, false, false, x, false, x, x, new Boolean(false), new Boolean(false), new Boolean(false), false, false, new Boolean(false), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, x, new Boolean(false), x, new Boolean(false), x, x, new Boolean(false), false, false, false, x, false, false, x, x, x, new Boolean(false), x, false, x, false, x, false, new Boolean(false)]) { e1 + p2; }");
/*fuzzSeed-248247344*/count=107; tryItOut("/*bLoop*/for (var yqbdkf = 0, \"\\uD2D1\".x = ((void options('strict'))); yqbdkf < 149; ++yqbdkf) { if (yqbdkf % 2 == 0) { (x); } else { Array.prototype.pop.apply(a0, [f0, g2.g2.m2]); }  } ");
/*fuzzSeed-248247344*/count=108; tryItOut("/*RXUB*/var r = (of = Proxy.createFunction(({/*TOODEEP*/})(-11), (Object.setPrototypeOf).apply)); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=109; tryItOut("g0 = this;");
/*fuzzSeed-248247344*/count=110; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - Math.cos((((x + (-0x100000000 + (Number.MAX_SAFE_INTEGER != x))) !== -Number.MIN_VALUE) , ( ~ x)))); }); ");
/*fuzzSeed-248247344*/count=111; tryItOut("");
/*fuzzSeed-248247344*/count=112; tryItOut("\"use strict\"; o0 = {};");
/*fuzzSeed-248247344*/count=113; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\3)|\\ua0a7{4,}|((?:[^]))|(?:[^]+|\\\\B)|(?!\\\\D*?)*?+?|$\", \"y\"); var s = (4277); print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=114; tryItOut("\"use strict\"; p2.toString = (function(j) { if (j) { try { print(uneval(i0)); } catch(e0) { } try { h0 = a2[14]; } catch(e1) { } o0.v0 = g0.eval(\"print(p1);\"); } else { v0 = undefined; } });function c(...NaN) { return /*FARR*/[false, new RegExp(\"(\\\\B)|\\\\3((?:(\\\\b))){3,260}|^+|((?=^{4,7})|($)?)?\", \"im\"), true, , true,  /x/ , ].filter } b0[x] = t1;");
/*fuzzSeed-248247344*/count=115; tryItOut("t0 = t2.subarray(12);");
/*fuzzSeed-248247344*/count=116; tryItOut("\"use strict\"; g1.v0 = (b0 instanceof m2);");
/*fuzzSeed-248247344*/count=117; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0.000000000000001, 2**53-2, -0x0ffffffff, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, Math.PI, 1.7976931348623157e308, 2**53, -(2**53), 0x100000000, -0x080000000, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53+2), 42, -0x100000000, -(2**53-2), 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, 0, -0, -1/0, 0x080000000]); ");
/*fuzzSeed-248247344*/count=118; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, -(2**53-2), Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 42, -Number.MAX_SAFE_INTEGER, -0x100000001, 1, 1.7976931348623157e308, -0x0ffffffff, 0x080000000, -0x07fffffff, -(2**53), 0x100000000, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -1/0, 0x07fffffff, -0x100000000, 0, -0x080000001, -(2**53+2), 2**53, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, 0x100000001, 0/0]); ");
/*fuzzSeed-248247344*/count=119; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xfb8ac955)))|0;\n    {\n      d0 = ((d1));\n    }\n    {\n      d0 = (+(0.0/0.0));\n    }\n    return (((0xb6a3ef9d)+(0xfc6e77e1)))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x07fffffff, 0, 42, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 2**53, -(2**53+2), 0x080000001, Math.PI, -0, 0x080000000, 0x100000001, -0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, -0x100000001, 1/0, Number.MAX_VALUE, 0x100000000, 2**53+2, 0x0ffffffff, -0x080000001, 1, 2**53-2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=120; tryItOut("M:do {Array.prototype.unshift.call(a0); } while(((4277)) && 0);");
/*fuzzSeed-248247344*/count=121; tryItOut("\"use strict\"; {m0.get(o2); }");
/*fuzzSeed-248247344*/count=122; tryItOut("if(29) v1 = (o2.t1 instanceof e0); else  if (false) {m1 + o0; }");
/*fuzzSeed-248247344*/count=123; tryItOut("eval(\"/*RXUB*/var r = new RegExp(\\\"((?!(?!\\\\u0090)|\\\\\\\\\\\\u95c9*??))\\\", \\\"gyim\\\"); var s = \\\"\\\"; print(uneval(r.exec(s))); \", new /*wrap1*/(function(){ /*ODP-3*/Object.defineProperty(s1, \"9\", { configurable: xigtwg, enumerable: false, writable: (x % 5 != 3), value: m2 });return function(q) { return q; }})()());");
/*fuzzSeed-248247344*/count=124; tryItOut("v0 = Object.prototype.isPrototypeOf.call(f1, f0);");
/*fuzzSeed-248247344*/count=125; tryItOut("/*ADP-1*/Object.defineProperty(a2, 2, ({set: y =>  { yield ([[], ]) = null } , configurable: (x % 5 != 0)}));");
/*fuzzSeed-248247344*/count=126; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(f1, t0);\n/*MXX3*/g0.Number.prototype.constructor = g1.Number.prototype.constructor;\n");
/*fuzzSeed-248247344*/count=127; tryItOut("const x = Math.acos(20);function f2(m2)  { \"use strict\"; g1.g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0.g0, fileName: null, lineNumber: 42, isRunOnce: \"\\u148C\", noScriptRval: false, sourceIsLazy: true, catchTermination:  ''  })); } ");
/*fuzzSeed-248247344*/count=128; tryItOut("mathy1 = (function(x, y) { return (mathy0((( + ((( ! -(2**53)) && ( + 0/0)) >>> 0)) >>> 0), (Math.pow(( + Math.round(Math.atan2(y, -0x080000000))), (x , x)) | 0)) + ( ! ( + Math.hypot(( + Math.asin(Math.pow(Math.atan2(x, y), y))), (((y >>> 0) ? y : (0/0 >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [(new String('')), (new Boolean(true)), [], '0', '\\0', -0, null, (new Number(-0)), '/0/', undefined, /0/, 0.1, false, objectEmulatingUndefined(), '', [0], ({toString:function(){return '0';}}), true, 1, (new Number(0)), ({valueOf:function(){return '0';}}), NaN, (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Boolean(false)), 0]); ");
/*fuzzSeed-248247344*/count=129; tryItOut("h1.iterate = f2;");
/*fuzzSeed-248247344*/count=130; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=131; tryItOut("\"use strict\"; var v1 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=132; tryItOut("for(let x = z in \"\\uE6DD\") {this.v0 = g1.eval(\"\\\"\\\\u8FE0\\\"\");print(null); }");
/*fuzzSeed-248247344*/count=133; tryItOut("v1 = (m2 instanceof a1);");
/*fuzzSeed-248247344*/count=134; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let c of /*MARR*/[ /x/g ,  /x/g , (0/0), (0/0),  /x/g ,  'A' ,  'A' ,  'A' ,  /x/g ,  /x/g ,  /x/g , (0/0),  'A' ,  /x/g , new String(''), (0/0), new String(''),  /x/g , (0/0),  /x/g , (0/0), (0/0), new String(''), (0/0),  'A' , (0/0), new String(''),  /x/g , new String(''),  'A' ,  /x/g ,  'A' , new String(''), new String(''), (0/0),  'A' ,  /x/g ,  /x/g ,  /x/g , new String(''),  /x/g ,  'A' ,  /x/g ]) { g1.toString = (function(j) { if (j) { v0 = Object.prototype.isPrototypeOf.call(o1, o2.o0.g2); } else { try { e0 + t2; } catch(e0) { } try { v0 = 4.2; } catch(e1) { } try { print(this.v1); } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(h0, t0); } }); }");
/*fuzzSeed-248247344*/count=135; tryItOut("\"use strict\"; var hwysqu = new ArrayBuffer(16); var hwysqu_0 = new Uint8Array(hwysqu); hwysqu_0[0] = 17; var hwysqu_1 = new Uint32Array(hwysqu); hwysqu_1[0] = -28; var hwysqu_2 = new Int16Array(hwysqu); hwysqu_2[0] = -22; var hwysqu_3 = new Float64Array(hwysqu); hwysqu_3[0] = 23; var hwysqu_4 = new Uint16Array(hwysqu); hwysqu_4[0] = 4; var hwysqu_5 = new Float32Array(hwysqu); a0 = new Array;f0(b0);print(uneval(h0));g2.v0 = a2.length;a1.forEach((function(j) { if (j) { try { m1.delete(o2.o1.t0); } catch(e0) { } try { for (var p in this.o2) { e1.__proto__ = m2; } } catch(e1) { } try { Object.defineProperty(this, \"v2\", { configurable: false, enumerable: (hwysqu_0[2] % 5 != 4),  get: function() {  return g2.runOffThreadScript(); } }); } catch(e2) { } v0 = evaluate(\"function f0(this.a0) \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var d3 = -1099511627777.0;\\n    var i4 = 0;\\n    d0 = (-((Float32ArrayView[2])));\\n    return ((((((0x0) % ((-(0xfa631d74))>>>(((0x1542bdeb) < (0x662978d5))-(0x71938660)))) >> ((0xf9598762)+(i4))) == (((1)-(0xffffffff)) >> (((imul((!((0x0) == (0x603d9fb))), ((16385.0) > (4.722366482869645e+21)))|0))+((+(0xffffffff)) == (1.0625)))))))|0;\\n  }\\n  return f;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: /(?!(?=(?!\\3(?!\\w))|\\B))/yi, noScriptRval: /\\\u00bd/gym, sourceIsLazy: false, catchTermination: (hwysqu_3[0] % 95 != 77) })); } else { try { s0 += s0; } catch(e0) { } try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = fillShellSandbox(evalcx('')); f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e1) { } o1 + ''; } }));m2.get(p1);\u3056 = linkedList(\u3056, 2829);print(hwysqu_0[0]);print(window);\nprint(\"\\u8BF8\");\n");
/*fuzzSeed-248247344*/count=136; tryItOut("mathy3 = (function(x, y) { return Math.min((Math.abs((Math.sinh((y | 0)) >>> 0)) >>> 0), (( ! ( + (Math.fround((Math.fround(Math.log10(Math.fround(x))) === y)) ? (Math.fround(-0x100000001) > Math.fround((( + ( ~ y)) & x))) : Math.pow(Math.max(0x100000001, Math.log(( + (x >>> 0)))), Math.fround((( + x) ? ( + (( - y) >>> 0)) : x)))))) | 0)); }); testMathyFunction(mathy3, [2**53-2, -0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -(2**53-2), 42, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 1, -0x080000000, 0x0ffffffff, -0, 1/0, -0x080000001, 0x100000001, -0x0ffffffff, 0x080000001, Math.PI, -Number.MIN_VALUE, 2**53, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -1/0, 2**53+2]); ");
/*fuzzSeed-248247344*/count=137; tryItOut("\"use strict\"; e1.has( /x/g );");
/*fuzzSeed-248247344*/count=138; tryItOut("\"use strict\"; yield;");
/*fuzzSeed-248247344*/count=139; tryItOut("\"use strict\"; v0 = (i1 instanceof o2);");
/*fuzzSeed-248247344*/count=140; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-281474976710657.0));\n    {\n      i1 = (i0);\n    }\n    return +((-7.737125245533627e+25));\n  }\n  return f; })(this, {ff: [,,]}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x07fffffff, 0x100000000, 0x100000001, -0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, -0x080000001, -0x0ffffffff, Number.MIN_VALUE, 2**53, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, 0.000000000000001, -0x080000000, -(2**53+2), 1, -(2**53), 2**53+2, -Number.MIN_VALUE, -1/0, 1.7976931348623157e308, -0x100000000, 0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 0, 0x0ffffffff, -0]); ");
/*fuzzSeed-248247344*/count=141; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (Math.atan2(( + Math.sqrt(Math.fround((Math.acos((y >>> 0)) >>> 0)))), (( + Math.min(( + Math.asin((Math.min((( - (x >>> 0)) >>> 0), x) >>> 0))), Math.pow(-0x080000000, y))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -0x080000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, 1, 42, 1/0, 2**53-2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -0x100000000, -(2**53), 0, -(2**53-2), 2**53, Number.MIN_VALUE, 0.000000000000001, Math.PI, 0x0ffffffff, -0x0ffffffff, -0x100000001, 0x080000001, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=142; tryItOut("v0 = evaluate(\"h0 = {};\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval:  /x/g , sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-248247344*/count=143; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=144; tryItOut("\"use strict\"; o2.s2 = a1.join(this.s0);");
/*fuzzSeed-248247344*/count=145; tryItOut("\"use strict\"; /*\n*/b = +x = this;a1 = a2[new RegExp(\"(?=$)\", \"g\").throw(yield  /x/ )];");
/*fuzzSeed-248247344*/count=146; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + ( - ( + Math.atan2(Math.exp(y), Math.sin((Math.imul(x, (Math.log2(((x ? Number.MIN_SAFE_INTEGER : (0x080000001 | 0)) >>> 0)) | 0)) | 0)))))) >> Math.fround(( + Math.tan(mathy1(-Number.MIN_SAFE_INTEGER, (Math.fround(( ~ 0.000000000000001)) >>> 0)))))); }); testMathyFunction(mathy2, [0x0ffffffff, 0.000000000000001, 0x100000000, 2**53, 1.7976931348623157e308, -0x07fffffff, -0x100000001, -0x080000000, -0, -Number.MIN_VALUE, 42, 1/0, -Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, 0/0, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), 2**53-2, 1, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 2**53+2, 0]); ");
/*fuzzSeed-248247344*/count=147; tryItOut("\"use strict\"; o2.o1.s0 += 'x';");
/*fuzzSeed-248247344*/count=148; tryItOut("\"use strict\"; m2.get(v0);");
/*fuzzSeed-248247344*/count=149; tryItOut("");
/*fuzzSeed-248247344*/count=150; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround(Math.fround((( + ( + ( ~ (-Number.MIN_SAFE_INTEGER | 0)))) === Math.fround(Math.fround((( + (( + ( ~ Math.sinh(( + (-0x080000000 ** ( + x)))))) + ( + x))) && Math.fround(-Number.MIN_SAFE_INTEGER))))))), Math.fround((((Math.imul((Math.sin((Math.fround(y) % Math.fround(x))) >>> 0), (Math.atanh(x) >>> 0)) | 0) != (Math.sin((x != (( + (y | 0)) | 0))) | 0)) | 0)))); }); testMathyFunction(mathy4, [0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, 2**53, 2**53-2, 0x080000000, 0x07fffffff, -0x0ffffffff, -1/0, 1/0, -Number.MIN_VALUE, 0x080000001, -0, 0x100000000, 0.000000000000001, 0/0, -0x080000001, -0x080000000, -0x100000000, -(2**53-2), -(2**53+2), -(2**53), -0x100000001, 0, 1.7976931348623157e308, 1, Math.PI, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=151; tryItOut("\"use strict\"; const x = x =  /x/ , b = eval = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: undefined, has: function() { return false; }, hasOwn: (q => q).apply, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(\"\\u4FB1\"), Date.prototype.toUTCString), c = timeout(1800), x = (undefined ?  \"\"  : this), cjyrau, mowmbt, d, x;const v0 = r0.unicode");
/*fuzzSeed-248247344*/count=152; tryItOut("mathy0 = (function(x, y) { return ( + ( + (Math.sinh(Math.min(((x >>> 0) | (-0x07fffffff >>> 0)), Number.MIN_SAFE_INTEGER)) ? (Math.atan2((Math.hypot(y, -Number.MIN_SAFE_INTEGER) >>> 0), (Math.pow(( + (y ? y : Math.fround(Math.fround(Math.log(Math.fround(y)))))), Math.imul((( + (Math.fround(-(2**53-2)) < ( + -0x080000000))) | 0), (x | 0))) >>> 0)) >>> 0) : (Math.ceil(( + (Math.log2((-0x07fffffff >>> 0)) >>> 0))) >>> 0)))); }); ");
/*fuzzSeed-248247344*/count=153; tryItOut("\"use strict\"; /*oLoop*/for (let tuxjuk = 0; tuxjuk < 7; ++tuxjuk) { v0 = this.g2.o2.o1.g2.runOffThreadScript(); } ");
/*fuzzSeed-248247344*/count=154; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.push.apply(a0, [m0, e0, timeout(1800)]);");
/*fuzzSeed-248247344*/count=155; tryItOut("/*tLoop*/for (let e of /*MARR*/[true, true, (0/0), true, true, true, true, true, true, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), true, (0/0), (0/0), true, (0/0), true, (0/0), (0/0), true, (0/0), true, (0/0), (0/0), (0/0), true, (0/0), (0/0), true, true, (0/0), true, true, true, (0/0), (0/0), true, true, (0/0), (0/0), true, (0/0), true, (0/0), (0/0), true, true, true, (0/0), true, true, (0/0), true, (0/0), true, true, true, (0/0), true, (0/0), true, true, (0/0), (0/0), true, (0/0), true, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), true, true, true, (0/0), (0/0), (0/0), true, (0/0), true, (0/0), true, true, true, (0/0), true, true, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), true, (0/0), (0/0), (0/0), (0/0), (0/0), true, (0/0), true]) { o1.g1.v0 = g1.g2.runOffThreadScript(); }");
/*fuzzSeed-248247344*/count=156; tryItOut("\"use strict\"; (window);\nprint(x);\n");
/*fuzzSeed-248247344*/count=157; tryItOut("\"use strict\"; /*infloop*/while(\u3056 ** c)\u0009{print(URIError()); }");
/*fuzzSeed-248247344*/count=158; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var asin = stdlib.Math.asin;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return +((Float32ArrayView[((~~(-1.001953125)) % (((i0)-(i0)-(/*FFI*/ff(((+asin(((1.888946593147858e+22))))), ((-17179869183.0)), ((-562949953421313.0)), ((-1.03125)), ((8193.0)))|0)) | ((i0)))) >> 2]));\n    {\n      (Uint16ArrayView[((i0)) >> 1]) = ((~~(-1025.0)));\n    }\n    i2 = (((((((!(i0))) << ((i2))))+(i3)) >> ((i2))));\n    i3 = (i3);\n    i2 = (0xff1e29f1);\n    return +((+(1.0/0.0)));\n    d1 = ((4277));\n    return +(((((~~(0.125)) != (~~(((i3)))))-(i2)) ^ ((-0x8000000))));\n  }\n  return f; })(this, {ff: function(y) { yield y; (x);; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_VALUE, 0, 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 2**53, -0, -Number.MIN_VALUE, 1/0, -0x07fffffff, 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 1, 0.000000000000001, 42, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), -1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), 0x080000001, -(2**53-2), -0x080000000, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0/0]); ");
/*fuzzSeed-248247344*/count=159; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround(mathy2(mathy1(Math.exp(y), (( ! y) | 0)), Math.fround((Math.fround(( + ( ! y))) % ( + (Math.hypot(( + y), (1 | 0)) | 0)))))) | Math.fround(( + ( - ( + Math.fround(( ! x)))))))); }); testMathyFunction(mathy4, [-1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -(2**53-2), 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, -0, -Number.MIN_VALUE, 1.7976931348623157e308, 1, 0x080000000, -(2**53), 0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, 0x0ffffffff, -0x07fffffff, 42, 2**53-2, Number.MIN_VALUE, 2**53+2, -0x080000001, 0.000000000000001, Math.PI, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 2**53, -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=160; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ~ ( + Math.log2(mathy0(( + (( + Math.tanh(( + Number.MIN_SAFE_INTEGER))) - ( + ((Math.fround(Math.fround(Math.pow(Math.fround(x), x))) << Math.fround(Number.MIN_SAFE_INTEGER)) | 0)))), Math.acos(42)))))); }); testMathyFunction(mathy3, /*MARR*/[ '' , {x:3},  '' , -Infinity, -Infinity, (1/0), (1/0),  '' , objectEmulatingUndefined(),  '' , (1/0),  '' ,  '' ]); ");
/*fuzzSeed-248247344*/count=161; tryItOut("mathy5 = (function(x, y) { return Math.pow(( + Math.pow(( - ( + Math.exp((x | 0)))), Math.hypot(( + Math.cbrt(Math.fround(Math.sinh(Math.fround(( ! y)))))), ( + Math.PI)))), (Math.pow(( + Math.min(x, y)), ( + y)) ? (( - (mathy0(( - Math.fround(y)), (Math.atan((-0x080000000 | 0)) | 0)) | 0)) | 0) : mathy4(((x ? Math.max((( + y) | 0), Math.fround(( + Math.fround(x)))) : x) | 0), (Math.hypot((( - y) - Math.PI), ( - ( + (y !== y)))) >>> 0)))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -0, 2**53+2, -(2**53+2), -0x100000000, -(2**53), 0/0, -1/0, -0x07fffffff, 42, 0x0ffffffff, 1, Math.PI, Number.MAX_VALUE, 0x080000000, 0.000000000000001, 1/0, 2**53-2, -0x100000001, 0, -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=162; tryItOut("\"use strict\"; e1.delete(h1);");
/*fuzzSeed-248247344*/count=163; tryItOut("mathy5 = (function(x, y) { return mathy2((( ~ (( + Math.exp((Math.fround(-(2**53+2)) && Math.fround(y)))) >>> 0)) >>> 0), (Math.log1p(( ~ Math.log2(( + (( + ( + Math.log2(y))) - ( + y)))))) >>> 0)); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -(2**53), -0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 2**53+2, 0x100000000, 0, -0x07fffffff, 0.000000000000001, 2**53-2, 0x080000000, -0x100000000, 0x080000001, 1, -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 1.7976931348623157e308, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -0, -(2**53-2), 42, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=164; tryItOut("mathy5 = (function(x, y) { return Math.hypot(( + Math.fround(( ~ Math.fround(Math.atan2((( ! Math.fround(2**53-2)) | 0), Math.fround((Math.fround((0x0ffffffff !== Math.fround(Math.log(x)))) >>> 0))))))), ( + mathy1((Math.max(x, Math.fround((( + (((x ? (x >>> 0) : ( + y)) >>> 0) >>> 0)) >>> 0))) | 0), (((( + Math.asinh(x)) >>> 0) , (((y << (Math.clz32((y / Math.pow(y, y))) >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 42, 0.000000000000001, 2**53+2, -0x07fffffff, 0x0ffffffff, 0x100000000, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 1, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, 2**53, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, -0, 0, 0x080000001, -0x0ffffffff, 1/0, -1/0, -0x100000001]); ");
/*fuzzSeed-248247344*/count=165; tryItOut("Object.seal(f0);");
/*fuzzSeed-248247344*/count=166; tryItOut("mathy5 = (function(x, y) { return ( + Math.imul(Math.acosh((Math.imul((Math.fround(( ! Math.fround(-0x0ffffffff))) >>> 0), (((( ~ x) >>> 0) ^ (-Number.MIN_VALUE >>> 0)) >>> 0)) | 0)), (mathy0((( + mathy3(( + mathy4((y >>> 0), Math.min(x, Math.fround(( ~ x))))), ( + (Math.imul((x | 0), (( - x) | 0)) >>> 0)))) | 0), (((1/0 < (x >>> 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy5, [-0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, 1, 1.7976931348623157e308, 0x080000001, -1/0, 0, -0x0ffffffff, 2**53-2, -0x100000000, 0x100000001, 0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 2**53, -(2**53+2), 42, Math.PI, 0/0, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -0]); ");
/*fuzzSeed-248247344*/count=167; tryItOut("for (var v of p0) { a2.pop(o0, i0, e0); }");
/*fuzzSeed-248247344*/count=168; tryItOut("print(t1);");
/*fuzzSeed-248247344*/count=169; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (Math.fround(Math.hypot(Math.fround(((( + ( ! (( ! (y | 0)) >>> 0))) ** (( + ( + (mathy4((Math.fround(Math.hypot(Math.fround(x), Math.fround(x))) | 0), (y | 0)) >>> 0))) >>> 0)) >>> 0)), Math.fround(Math.abs(y)))) < Math.fround(Math.atan2(( + ((((x | 0) , (-Number.MIN_VALUE | 0)) | 0) <= ( ! y))), ((( ~ (y >>> 0)) >>> 0) && Math.asin(Math.cos(Math.cos(y)))))))); }); ");
/*fuzzSeed-248247344*/count=170; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.max(( ~ ((((Math.min(Math.fround(x), (x || ( + y))) | 0) >>> 0) ? (Math.hypot(Math.max(( + 0x0ffffffff), Math.fround(x)), x) >>> 0) : (Math.imul(( + (Math.atan((x >>> 0)) >>> 0)), (Math.fround((( + y) | 0)) | 0)) >>> 0)) >>> 0)), (Math.ceil(Math.min(x, -0x080000001)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[(1/0), (-1/0), (1/0), (void 0), (1/0), (void 0), (1/0), (1/0), (void 0), (void 0), (1/0), (-1/0), (void 0), (1/0), (void 0), (void 0), (1/0), (1/0), (void 0), (void 0), (void 0), (1/0), (1/0)]); ");
/*fuzzSeed-248247344*/count=171; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"[^]\", \"yim\"); var s = \"\\u78cc\"; print(r.exec(s)); ");
/*fuzzSeed-248247344*/count=172; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=173; tryItOut("\"use strict\"; throw StopIteration;");
/*fuzzSeed-248247344*/count=174; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.atan2(((( ! Math.imul(Math.atan2((mathy1(( + 2**53+2), ( + Number.MIN_SAFE_INTEGER)) - y), x), (Math.imul(Math.fround((( ~ Math.sqrt(y)) >>> 0)), (Math.fround((Math.max(y, x) >>> 0)) | 0)) | 0))) ? Math.abs(0x100000001) : mathy0(Math.fround(( + Math.hypot((y != ( + x)), (x ** Number.MAX_SAFE_INTEGER)))), Math.fround(Math.hypot((( + y) || Number.MAX_SAFE_INTEGER), Math.fround(-0x080000001))))) >>> 0), (( + mathy0(( + ( + (( + y) > (((y ? (Math.fround((Math.fround(0/0) >>> Math.fround(-0x100000001))) | 0) : ((x >>> y) | 0)) | 0) >>> 0)))), mathy0((void options('strict')), Math.sign(((Math.fround(( ! Number.MAX_VALUE)) ? ( + y) : ( + -Number.MAX_VALUE)) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0x0ffffffff, -0, 0x100000001, 2**53, 1/0, -0x080000001, 0x100000000, Math.PI, 0x07fffffff, 2**53+2, 0x080000001, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -0x100000001, 1, -(2**53-2), -Number.MIN_VALUE, 42, -0x100000000, -0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), -0x080000000, 2**53-2, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0]); ");
/*fuzzSeed-248247344*/count=175; tryItOut("\"use strict\"; print(uneval(this.f0));");
/*fuzzSeed-248247344*/count=176; tryItOut("g2 = v1;");
/*fuzzSeed-248247344*/count=177; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.atan2(( + Math.pow((( + x) >>> 0), (((((mathy1((Math.atan2(( + mathy3((x >>> 0), ( + ( + ( ! ( + x)))))), y) | 0), ((( ! (y | 0)) | 0) | 0)) | 0) >>> 0) > (y >>> 0)) >>> 0) >>> 0))), (( - ((((mathy3(y, (Math.max(x, Math.fround(mathy2(y, y))) | 0)) | 0) < (x | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [2**53, -0, Math.PI, -(2**53), -0x100000001, 0x07fffffff, -0x080000001, 0x100000000, -0x100000000, -0x07fffffff, -0x080000000, -(2**53+2), 0/0, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 1, 42, -1/0, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 1.7976931348623157e308, 0x080000000, 0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=178; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+((((Math.max(2, 547533754))))>>>(((((i1)+(i1))>>>(x)) >= ((((0xb7720035) ? (0xffffffff) : (0x4aa441a1))*0xa2c97)>>>(-((0x63ed4c95) != (0xffffffff)))))*-0x2e38e)));\n    d0 = (+(1.0/0.0));\n    return (((((0xce33a02a)-(i1)) << ((abs((abs((0x52c93f01))|0))|0) / (((Uint32ArrayView[0])) ^ ((i1)*-0x485d2))))))|0;\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var zlcknv = String.prototype.toLocaleLowerCase; ([])(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=179; tryItOut("tufsbn();/*hhh*/function tufsbn(w, window, [x(((makeFinalizeObserver('tenured')))), , x] = (let (c) \"\\u1C49\"), b, e, d, x, e = /[]/gi, x, x, b, x, window, w, a, window, c = false, x = window, y, window, x = this, d, eval =  /x/g , c, e, x, x, b, x =  /x/g , x, this. , \u3056, NaN,  , x, d, \u3056, a, x =  '' , x, x, x, y, window, x, x = \"\\u8B86\", x, x, x = z, w, y =  '' , x, x){yield;function this.NaN(NaN) { \"use strict\"; \"use asm\"; {} } print(x);\no0.t0.set(a1, ({valueOf: function() { print((new (-Number.MIN_VALUE)()));return 3; }}));\n}");
/*fuzzSeed-248247344*/count=180; tryItOut("({/*toXFun*/toSource: function() { return this; }, /*toXFun*/valueOf: (function(j) { f0(j); }) });");
/*fuzzSeed-248247344*/count=181; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    d0 = (((i1) ? (0x609add7) : (0x4075d128)) ? (NaN) : (262145.0));\n    (Uint16ArrayView[4096]) = (-0x11c30*(i1));\n    i1 = (0xffffffff);\n    d0 = (17592186044415.0);\n    {\n      (Float32ArrayView[((i1)+((((0x8fe9ae9d)-(0x6c2eb474)-(0xfe22eba9))>>>((0xd6506cf7))) != (0xc8aed863))) >> 2]) = ((d0));\n    }\n    {\n      i1 = (0xd67c3167);\n    }\n    i1 = (-0x56125f7);\n    return ((((((0x3a63bfc9))>>>((i1)+(i1))))))|0;\n  }\n  return f; })(this, {ff: (new Function(\"a2.__proto__ = e0;\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[ /x/g , 0xB504F332, new Number(1.5), new Number(1.5), new Number(1.5), 0xB504F332,  /x/g ,  /x/g , x, new Number(1.5),  /x/g , 0xB504F332, x, x, 0xB504F332, 0xB504F332, x, new Number(1.5), x,  /x/g , x, new Number(1.5),  /x/g , new Number(1.5), 0xB504F332, 0xB504F332, x, 0xB504F332, x, 0xB504F332, x, x,  /x/g ,  /x/g ,  /x/g , x, 0xB504F332, 0xB504F332, new Number(1.5), x,  /x/g , 0xB504F332, x, new Number(1.5), x, x, x, 0xB504F332, 0xB504F332, x, x, 0xB504F332,  /x/g ,  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/g ,  /x/g ,  /x/g , x, new Number(1.5),  /x/g , x, 0xB504F332, new Number(1.5), x, 0xB504F332, 0xB504F332, new Number(1.5), new Number(1.5), x, 0xB504F332, x, new Number(1.5), 0xB504F332, x, new Number(1.5), x, x, 0xB504F332, 0xB504F332, new Number(1.5), x, new Number(1.5), new Number(1.5),  /x/g , 0xB504F332, x,  /x/g , x, x, 0xB504F332, x, 0xB504F332]); ");
/*fuzzSeed-248247344*/count=182; tryItOut("/*oLoop*/for (var spvyfi = 0; spvyfi < 5; ++spvyfi) { e1.has(g1); } ");
/*fuzzSeed-248247344*/count=183; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.abs((y != Math.trunc(Math.atan2(Math.fround(Math.atan2(Math.fround(1.7976931348623157e308), Math.fround(y))), ( + ( - (((x >>> 0) + x) >>> 0))))))), ((((y + -(2**53-2)) - Math.fround(Math.max(( ! y), (Math.fround(mathy0((42 >>> 0), Math.fround((Math.fround(-0x100000000) ? Math.fround(y) : Math.fround(-(2**53-2)))))) >>> 0)))) >>> 0) * (( + (( + Math.cos((Math.ceil(Math.fround(x)) | 0))) , ((( + Math.fround(( ~ Math.fround(x)))) | 0) || (y >>> 0)))) >>> 0))); }); testMathyFunction(mathy2, [0x0ffffffff, -0x0ffffffff, 2**53-2, 0.000000000000001, -0x07fffffff, -(2**53+2), -0x100000000, 0/0, 0x07fffffff, -0x100000001, 0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000001, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x080000001, 2**53+2, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -0, 0, 0x100000001, 42, 1/0]); ");
/*fuzzSeed-248247344*/count=184; tryItOut("e0.add(g1);");
/*fuzzSeed-248247344*/count=185; tryItOut("\"use strict\"; print(x);\nprint(x);\n");
/*fuzzSeed-248247344*/count=186; tryItOut("t2[({valueOf: function() { /*tLoop*/for (let z of /*MARR*/[new Number(1), new Number(1), new Number(1), c, new Number(1), c, new Number(1), new Number(1), c, c, new Number(1), new Number(1), new Number(1), c, new Number(1), c, new Number(1), new Number(1), c, new Number(1)]) { var hfynzp = new ArrayBuffer(0); var hfynzp_0 = new Uint16Array(hfynzp); print(hfynzp_0[0]); s0 += this.s0; }return 8; }})] = x;");
/*fuzzSeed-248247344*/count=187; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (((!(((/*FFI*/ff(((((-0x8000000)) & ((0x65915337)))), ((((-0x8000000)) & ((0xfa270ac5)))))|0) ? ((imul((0xfa61c710), (0xffffffff))|0) > (((0x8040e61b)) & ((0xd687b369)))) : ((abs((((0xfefc8de2)) << ((0xf97f3116))))|0))) ? ((abs((0x54a09627))|0) > ((-((-2.3611832414348226e+21) < (4.835703278458517e+24)))|0)) : (i2)))));\n    return ((((let (e=eval) e))))|0;\n  }\n  return f; })(this, {ff: ((function(y) { yield y; return [z1];; yield y; }).call).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, -(2**53+2), -0x0ffffffff, 0x07fffffff, 1/0, 0.000000000000001, -0x100000001, 42, -0x100000000, 2**53+2, 2**53, Math.PI, 0, Number.MAX_VALUE, 1, 0/0, 2**53-2, -0x080000000, -0x080000001, 0x0ffffffff, -0, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, -(2**53-2), -0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=188; tryItOut("\"use strict\"; g1.s1 += s2;");
/*fuzzSeed-248247344*/count=189; tryItOut("/*tLoop*/for (let d of /*MARR*/[function(){}, function(){}, (-1/0), (-1/0), this, function(){}, (-1/0), function(){}, (-1/0), function(){}, function(){}, function(){}, this, function(){}, this, function(){}, (-1/0), this, (-1/0), (-1/0), function(){}, (-1/0), function(){}, this, this, function(){}, function(){}, (-1/0), this, (-1/0), function(){}, this, (-1/0), this, this, function(){}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), this, function(){}, function(){}, (-1/0), (-1/0), this, function(){}, this, (-1/0), function(){}, function(){}, (-1/0), (-1/0), (-1/0), this, function(){}, function(){}, (-1/0), function(){}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), this, function(){}, (-1/0), (-1/0), function(){}, function(){}, this, function(){}, this, function(){}, function(){}, function(){}, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), this, this, this, function(){}, (-1/0), (-1/0), (-1/0), this]) { (eval(\"print(x);\", -22)); }");
/*fuzzSeed-248247344*/count=190; tryItOut("return;");
/*fuzzSeed-248247344*/count=191; tryItOut("/*bLoop*/for (kxnfns = 0; kxnfns < 27; ++kxnfns) { if (kxnfns % 58 == 2) { print(x); } else { m0.delete(v2); }  } ");
/*fuzzSeed-248247344*/count=192; tryItOut("a0.unshift(g1.g2.s1);");
/*fuzzSeed-248247344*/count=193; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.imul(( - x), y) % (Math.atan(x) ? y : Math.imul(Math.min((y | 0), Math.log2(y)), ((((mathy0((( + Math.cbrt(( + y))) >>> 0), (x | 0)) | 0) | 0) | Math.fround(Math.imul(x, (-0x080000000 | 0)))) | 0)))) >>> mathy1(Math.fround(Math.imul(Math.fround((( ! ( + x)) | 0)), Math.fround(y))), (( + (( ! ( + 0x07fffffff)) | 0)) | 0))); }); testMathyFunction(mathy4, [-0x080000001, -Number.MAX_VALUE, -(2**53), 2**53, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, 0, 1, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 0x080000000, 0.000000000000001, Math.PI, 0x100000000, 42, 2**53-2, 1.7976931348623157e308, 0x080000001, 0x100000001, Number.MIN_VALUE, -0x100000001, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 0/0, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=194; tryItOut("/*RXUB*/var r = /${3}/g; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=195; tryItOut("var mcdkpb, y = x;print((27 >= \"\u03a0\"));");
/*fuzzSeed-248247344*/count=196; tryItOut("\"use asm\"; /*infloop*/for(let eval = /((?=^\\b\\b)\\3){0,1}/yim; this; this) {( \"\" );m2.delete(this.m1); }");
/*fuzzSeed-248247344*/count=197; tryItOut("this.e0 + '';s2 += s1;");
/*fuzzSeed-248247344*/count=198; tryItOut("a1.sort(f1, h0, e0);");
/*fuzzSeed-248247344*/count=199; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(((Math.min((Math.acosh((( ~ (y >>> 0)) >>> 0)) >>> 0), ( - Math.fround(Math.fround(( ~ x))))) % Math.trunc(Math.acosh((( - mathy0(y, Math.max(x, x))) | 0)))) >>> 0)); }); testMathyFunction(mathy1, [-0x100000001, Number.MAX_SAFE_INTEGER, 2**53, -(2**53), -0x080000000, -(2**53-2), -Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 1.7976931348623157e308, 0.000000000000001, 2**53-2, 0x100000000, 0x100000001, 0x080000001, 0x080000000, Math.PI, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 1, -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, Number.MAX_VALUE, 0/0, 0, 1/0, 2**53+2, 42, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=200; tryItOut("v0 = (p0 instanceof b2);");
/*fuzzSeed-248247344*/count=201; tryItOut("let (c) { /*oLoop*/for (var vfsigw = 0, c = x; vfsigw < 11; ++vfsigw) { print(c); }  }");
/*fuzzSeed-248247344*/count=202; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 562949953421311.0;\n    d3 = (+/*FFI*/ff(((~~(d3))), ((-((-4294967297.0)))), ((d3)), (x = x), ((((i0)+(0xf688061a)) & (((0xffffffff))+(x)+(/*FFI*/ff(((1152921504606847000.0)), ((2097151.0)))|0)))), ((imul((/*FFI*/ff(((0x23cd4d09)), ((68719476736.0)), ((1.0078125)), ((-4.0)), ((-36028797018963970.0)))|0), (i1))|0)), ((-72057594037927940.0)), ((imul((0x35131903), (0xffffffff))|0))));\n    switch ((abs((((0xb1ebeecb)-(0xcf0cafa9)+(0xfdc380ad)) ^ ((0x4de70045) % (0x6ac33b4c))))|0)) {\n      case 0:\n        {\n          (Float64ArrayView[((i1)+((((0x3d27e789)-(-0x8000000))>>>((0xa37122b6)-(0xfcbac54f))) == (0xbe6ad7f3))) >> 3]) = ((Float64ArrayView[2]));\n        }\n        break;\n      case -3:\n        switch (((((0x159ca3ac) ? (0xffffffff) : (0xffffffff))) >> (((0x5cfa0f5a))-(i2)))) {\n        }\n        break;\n    }\n    i1 = (((((imul((i0), ((0xff3af261) ? (0xf9c51bf1) : (0xffffffff)))|0))-(Math.cbrt(w)))>>>((i0)+(0x13c1dcc8)-(-0x8000000))) != (((i1))>>>(((([] = \"\\u25C0\" % d)))+(/*FFI*/ff(((-513.0)), ((+floor(((+(((-0x20c93d)) ^ ((0x6eb5973f)))))))), ((+(((0xd2254f8a)) & ((0xc575cf08))))), ((~~(16385.0))), ((-2147483648.0)))|0))));\n    i1 = ((0xd1e838e6));\n    i2 = ((-0x8000000) ? (0x4c1627b0) : (i2));\n    return +((((d3)) * ((1.9342813113834067e+25))));\n  }\n  return f; })(this, {ff: mathy1}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [1.7976931348623157e308, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, Math.PI, 1, 0x07fffffff, -0x100000000, 2**53-2, 0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -1/0, 0x100000001, -(2**53), -0x0ffffffff, 0x100000000, 1/0, -0x100000001, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), Number.MAX_VALUE, -0x080000001, 0x080000001, 42, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=203; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[]) { Object.freeze(s0); }");
/*fuzzSeed-248247344*/count=204; tryItOut("\"use strict\"; \"use asm\"; e0.add(m2);");
/*fuzzSeed-248247344*/count=205; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"i\"); var s = \"\\n\\n\\n\\naa1a1\\n\\n\"; print(s.replace(r, new RegExp(\"\\\\w\", \"gim\"))); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=206; tryItOut("\"use strict\"; a0.length = 6;");
/*fuzzSeed-248247344*/count=207; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(((Math.atan2(( - x), ( - ( ! Math.asinh(( + (y < y)))))) | 0) - Math.fround(Math.cbrt(( + (( + (Math.min(Math.fround(Math.cbrt(y)), Math.ceil(x)) && ( + (Math.fround(y) !== -0x07fffffff)))) / ( + ( + (( + y) ? ( + Math.min(Math.fround(Math.max(x, ( + y))), Math.hypot(x, x))) : ( + Math.atan2(y, (( ~ y) >>> 0)))))))))))); }); ");
/*fuzzSeed-248247344*/count=208; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.atan2(( ! (Math.expm1(Math.cosh(0.000000000000001)) | 0)), Math.log(mathy0((Math.hypot((mathy3(y, x) | 0), (Math.cosh(x) | 0)) >>> 0), ( + mathy0((Math.round(( + Math.atan2(( + x), ( + y)))) | 0), ( - Math.hypot(( + mathy4(Number.MAX_SAFE_INTEGER, 0/0)), y))))))); }); testMathyFunction(mathy5, [-0x100000001, -Number.MIN_VALUE, 1/0, 0/0, 1, 0.000000000000001, 0x100000000, -0x100000000, -0x080000000, 0, -0x0ffffffff, -0x080000001, 0x100000001, -(2**53+2), -0, 2**53+2, 0x080000001, 42, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, Math.PI, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=209; tryItOut("\"use strict\"; /*hhh*/function vbzvrq(x){/*RXUB*/var r = new RegExp(\"\\\\1(?:(?=\\\\b){2047,})|\\\\u0067|(?!$){17179869183,17179869187}.$+*[]*\", \"yi\"); var s = \"\"; print(uneval(s.match(r))); }vbzvrq();const e = ({ set x(x)\"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    (Float64ArrayView[0]) = ((+(~~(d1))));\n    {\n      switch ((abs(((((-9223372036854776000.0) < (-1.5474250491067253e+26))) >> ((0xffffffff))))|0)) {\n        case -3:\n          d1 = (d1);\n          break;\n        case -1:\n          d1 = (4.835703278458517e+24);\n          break;\n        case 0:\n          {\n            d1 = (-1.25);\n          }\n          break;\n        case 1:\n          i0 = (((undefined) >> ((0x356a663f))));\n          break;\n        case 0:\n          d1 = (+atan2(((16777216.0)), ((d1))));\n          break;\n        case -3:\n          i0 = (0x28932da6);\n        case -3:\n          i0 = (0xffffffff);\n          break;\n        default:\n          d1 = (((-1.1805916207174113e+21)) - ((Float64ArrayView[((i0)) >> 3])));\n      }\n    }\n    return +(((i0) ? (d1) : (d1)));\n  }\n  return f; });");
/*fuzzSeed-248247344*/count=210; tryItOut("\"use strict\"; o2.m0.get((4277));");
/*fuzzSeed-248247344*/count=211; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 2199023255552.0;\n    {\n      {\n        i1 = ((((0xc9e6225b)+((0xf9de782a) ? (0xffffffff) : ((0x3cef0c5d) == (0x712ff69f)))-(/*FFI*/ff(((((0xffffffff)) | ((0x1a3f24b7)))))|0)) | ((((i1)-(-0x8000000))>>>((i1)+((0x574468c3))-(!(0xfbf22c5e)))) / ((((0x4f2b8e77))+(!(0x69c88977))-(0xfdb8c8a4))>>>((i1))))));\n      }\n    }\n    i1 = (/*FFI*/ff(((((i1)-((0x8fa4d356) ? (/*FFI*/ff(((abs((((-0x17f8e94)) & ((0x8b9002be))))|0)))|0) : ((0xfd75f579) ? (0x1c000622) : (0xa362221)))) & ((/*FFI*/ff(((d2)), ((d2)), ((-2.3611832414348226e+21)))|0)+((-6.189700196426902e+26) != (+atan2(((+(-1.0/0.0))), ((d0)))))-(0xb267776e)))), ((-3.094850098213451e+26)), ((-0x8000000)), (((0x79da6*((((0x4da0e807)) ^ ((0x22172f7))))) << ((i1)+(i1)-(i1)))), ((-0x8000000)), (((0x16892*(/*FFI*/ff(((73786976294838210000.0)), ((-8796093022209.0)), ((-2251799813685247.0)))|0)) << ((!(-0x8000000))*0xbc77b))), ((Math.max(/*MARR*/[(1/0), (1/0), (1/0), [z1], (1/0), [z1], (1/0), [z1], -Infinity, -Infinity, function(){}, -Infinity, [z1], function(){}, -Infinity, [z1], -Infinity, -Infinity, function(){}, (1/0), [z1], [z1], (1/0), -Infinity, [z1], function(){}, function(){}, function(){}, -Infinity, function(){}, [z1], [z1], [z1], [z1], [z1], [z1], (1/0), [z1], (1/0), -Infinity, [z1], [z1], (1/0), [z1], function(){}, -Infinity, (1/0), function(){}, function(){}, function(){}, function(){}, function(){}, (1/0), -Infinity, function(){}, (1/0), function(){}, -Infinity, -Infinity].filter(decodeURI), intern(/*oLoop*/for (var utcote = 0; utcote < 14; ++utcote) {  } )))), ((((0xf8b0d39e)) & ((0xfa9529d6)))), ((+(1.0/0.0))), ((576460752303423500.0)), ((-3.022314549036573e+23)), ((65537.0)), ((513.0)), ((-17592186044416.0)), ((-33554432.0)), ((-3.022314549036573e+23)), ((-147573952589676410000.0)), ((4611686018427388000.0)), ((1.5)))|0);\n    return +((36028797018963970.0));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), -0, 0x0ffffffff, 2**53, 1, 0x080000001, -(2**53), -1/0, -0x080000000, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0, 42, -0x0ffffffff, 2**53+2, 1.7976931348623157e308, 0x080000000, Math.PI, Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, -Number.MAX_VALUE, 1/0, 0.000000000000001, -(2**53+2), -0x07fffffff, 0x100000001, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=212; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.abs(Math.asin(Math.fround(mathy0(( + (x && ( + Math.hypot(( + x), ( + -Number.MIN_SAFE_INTEGER))))), Math.fround((mathy0((x | 0), (mathy0(-0, y) | 0)) | 0)))))); }); testMathyFunction(mathy1, [1.7976931348623157e308, 0x0ffffffff, 0/0, 0x07fffffff, -0x100000000, 0x080000001, -0x080000000, 1/0, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 0x080000000, -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -0, Number.MIN_VALUE, -(2**53+2), -0x100000001, -Number.MAX_VALUE, 0, Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -1/0, 1, -(2**53), 2**53+2, 42, 2**53-2]); ");
/*fuzzSeed-248247344*/count=213; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((Math.imul(((((Math.fround((Math.fround((Math.fround(((x | 0) - y)) * Math.fround(x))) ** Math.fround(x))) ^ (( - (y | 0)) | 0)) >>> 0) ? ((Math.tanh((y >>> 0)) >>> 0) >>> 0) : (Math.fround((x >= ( + (( + ((( - -(2**53)) | 0) >>> 0)) >>> 0)))) >>> 0)) >>> 0), ( ! Math.imul(( + (Math.fround(-Number.MIN_VALUE) && ( ~ (Math.atan2(x, y) | 0)))), -(2**53-2)))) ? (( - ( + (((Math.asin(x) ? y : x) == ( + ((y >> Number.MIN_VALUE) * ( + y)))) * y))) ^ ( + ((Math.atan2(Math.atan2(( + 0x080000000), ( + x)), ( - y)) | 0) > -Number.MAX_VALUE))) : Math.fround(Math.min(Math.fround(Math.tanh(Math.tan(y))), Math.fround(Math.fround(( + Math.fround(Math.fround(( ~ (( + (( + (( ~ (Number.MAX_SAFE_INTEGER | 0)) | 0)) >>> ( + 1))) | 0)))))))))) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[function(){}]); ");
/*fuzzSeed-248247344*/count=214; tryItOut("mathy5 = (function(x, y) { return (Math.pow(( + (Math.ceil((Math.fround((Math.fround((Math.tanh(( + y)) >>> 0)) || Math.fround(( + ( + ( + 0x100000000)))))) | 0)) >>> 0)), Math.fround((Math.fround(Math.fround((Math.fround(((y >>> 0) + Math.pow(( + y), x))) && Math.fround(mathy2(( + (( ~ (x >>> 0)) >>> 0)), ( + ( + ( ! ( + y))))))))) / ( ~ y)))) >>> 0); }); testMathyFunction(mathy5, /*MARR*/[ '\\0' , NaN, new Number(1.5), NaN, NaN,  '\\0' , new Number(1.5), NaN, new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' , new Boolean(true),  '\\0' , new Boolean(true), new Number(1.5), NaN, NaN, NaN, new Boolean(true),  '\\0' , new Number(1.5), new Number(1.5), NaN,  '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , NaN]); ");
/*fuzzSeed-248247344*/count=215; tryItOut("testMathyFunction(mathy2, [Number.MIN_VALUE, 0x0ffffffff, -0, 0x080000001, 1, -(2**53-2), Number.MAX_VALUE, 42, -(2**53), -0x080000001, 0x100000000, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x100000001, -0x07fffffff, -1/0, 2**53-2, 0x07fffffff, 0x080000000, 0/0, 2**53, 2**53+2, -0x100000000, 1/0, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=216; tryItOut("\"use strict\"; this.v0 = Object.prototype.isPrototypeOf.call(t1, p0);");
/*fuzzSeed-248247344*/count=217; tryItOut("v1 = o1.a0.length;");
/*fuzzSeed-248247344*/count=218; tryItOut("/*vLoop*/for (var bamugz = 0; bamugz < 57; ++bamugz) { var e = bamugz; ( \"\" ); } ");
/*fuzzSeed-248247344*/count=219; tryItOut("for(let c in /*FARR*/[((Set.prototype.clear)(x)\u0009), intern((void version(185)))]) for(let e of new Array(-16)) yield x;");
/*fuzzSeed-248247344*/count=220; tryItOut("\"use strict\"; let x = Math.pow(0, new RegExp(\"(?:\\\\w|[^\\\\u0023-\\\\uF9d8\\\\uEA1E-\\u0082]|(?!\\\\w{1,}^??)?)\", \"ym\")) ? x : (4277), fpqgaf, rkkkxp, x = (({wrappedJSObject:  ''  })), {c, c: w, \u3056} = let (z = [[1]]/*\n*/) window, \u3056 = Math.pow(14, 18), x = (void version(180)), \u3056 = a **  , ynrgjz, eval = \"\\u81A2\";e1.delete(s0);");
/*fuzzSeed-248247344*/count=221; tryItOut("\"use strict\"; /*hhh*/function wivblt(){return;}wivblt([,,]);");
/*fuzzSeed-248247344*/count=222; tryItOut("o0.o2.valueOf = (function() { v1.toSource = (function() { try { for (var p in m0) { i2.send(t0); } } catch(e0) { } try { t2.set(t2, 19); } catch(e1) { } try { delete h2.set; } catch(e2) { } a1 = Array.prototype.filter.apply(a0, [(function mcc_() { var kquvsk = 0; return function() { ++kquvsk; if (/*ICCD*/kquvsk % 7 == 6) { dumpln('hit!'); a0.reverse(b1, i2, t2, this.e0); } else { dumpln('miss!'); v2 = Object.prototype.isPrototypeOf.call(o1.b2, e0); } };})()]); return t2; }); return f1; });");
/*fuzzSeed-248247344*/count=223; tryItOut("for(let x = /*MARR*/[3/0, (0/0), (0/0), new Number(1), 3/0, new Number(1), (0/0), 3/0, (0/0), 3/0, (0/0), new Number(1), new Number(1), new Number(1), 3/0, 3/0, new Number(1), new Number(1), new Number(1), 3/0, 3/0, 3/0, 3/0, (0/0), 3/0, 3/0, (0/0), 3/0, 3/0, 3/0, new Number(1), 3/0, new Number(1), 3/0, new Number(1), (0/0), 3/0, new Number(1), 3/0, (0/0), (0/0), new Number(1), new Number(1), new Number(1), 3/0, (0/0), 3/0, 3/0, (0/0), (0/0), new Number(1), new Number(1), 3/0, (0/0), (0/0), (0/0), 3/0, 3/0, (0/0), 3/0, 3/0, new Number(1)] in ({})) {const eval, llwohi, c;print(0);print(Number.MAX_SAFE_INTEGER); }");
/*fuzzSeed-248247344*/count=224; tryItOut("\"use strict\"; (delete c.w);");
/*fuzzSeed-248247344*/count=225; tryItOut("e0.has(s1);\n([[]]());\n");
/*fuzzSeed-248247344*/count=226; tryItOut("\"use asm\"; Array.prototype.sort.call(a0, (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30) { var r0 = a6 / a1; var r1 = 0 + a23; var r2 = 2 / a13; var r3 = 4 ^ 6; var r4 = a7 * 2; var r5 = a0 & a2; var r6 = 1 ^ 0; var r7 = a13 * a28; var r8 = a30 - r1; print(a12); var r9 = 0 & 5; var r10 = r8 % a2; var r11 = 4 ^ 4; var r12 = r8 + a24; var r13 = 7 & a30; var r14 = 9 - 7; var r15 = r6 / a15; var r16 = 9 + a14; var r17 = a3 / 5; var r18 = a27 & 5; var r19 = a8 % a6; a21 = 5 - r19; var r20 = a8 + 0; var r21 = r10 / a3; var r22 = a25 * 4; r10 = r10 ^ 6; var r23 = a21 * a23; print(r14); var r24 = a4 - a11; var r25 = a2 / a3; var r26 = a14 & r10; var r27 = 9 ^ r17; var r28 = a23 | 6; var r29 = r5 & a30; var r30 = 0 & a17; a6 = a30 | r5; var r31 = r28 * 7; var r32 = a19 + r2; a16 = r4 - r9; var r33 = r10 / 7; a16 = 9 * 8; var r34 = r11 - 6; var r35 = r3 - r13; var r36 = a1 / a24; var r37 = r0 + r34; a27 = 9 & 6; var r38 = 3 | a16; var r39 = a14 % a11; var r40 = 2 + a21; var r41 = 7 * r2; var r42 = r39 * a17; var r43 = r6 - r34; var r44 = r4 & r5; var r45 = 7 ^ a1; var r46 = r44 % r0; var r47 = a25 % a5; var r48 = r0 & 5; var r49 = r0 & r45; var r50 = r23 / 0; a22 = 3 ^ 8; var r51 = a24 & a25; var r52 = r50 * a7; var r53 = 7 % 5; var r54 = r23 | 2; var r55 = a8 * r26; var r56 = r13 & 8; var r57 = r48 & r56; r31 = 4 * r3; print(a14); var r58 = r48 | r19; a10 = r3 * r12; var r59 = r4 * r57; var r60 = 5 + 6; var r61 = 9 | a7; r20 = r0 - 5; var r62 = r32 ^ r60; var r63 = a16 + r29; print(r43); var r64 = r5 % r31; var r65 = 0 - r52; r32 = r17 | r26; var r66 = r22 + r64; var r67 = 8 ^ r1; var r68 = 4 & 4; var r69 = 8 / r42; var r70 = 7 - 1; var r71 = a10 | r65; var r72 = r4 % a12; var r73 = r16 ^ r37; var r74 = 5 ^ a7; print(r70); var r75 = 8 + r57; print(r60); var r76 = r21 / r51; var r77 = 4 % r21; print(r21); var r78 = 1 + a1; var r79 = 2 * a15; r5 = 3 % r30; r70 = a5 * a6; r75 = r48 | a0; var r80 = 8 % a21; var r81 = 4 / r21; print(r5); var r82 = 7 / r56; var r83 = r40 * 6; var r84 = r16 * 4; var r85 = 3 % a5; var r86 = 5 / r5; print(r3); r86 = a27 % a30; r42 = r55 % a19; var r87 = r48 | r18; x = r44 - 7; print(a19); var r88 = r35 % r40; var r89 = a8 & r84; r63 = a14 & 3; var r90 = r64 + a22; var r91 = a21 / 4; var r92 = 8 & r14; var r93 = 6 ^ a8; var r94 = 5 * 7; print(r17); var r95 = r56 ^ 7; var r96 = 5 | r65; r96 = 5 | 8; r13 = r69 - r90; return a15; }), f0);");
/*fuzzSeed-248247344*/count=227; tryItOut("this.v0 = t2.byteLength;");
/*fuzzSeed-248247344*/count=228; tryItOut("print(10);");
/*fuzzSeed-248247344*/count=229; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan2((((Math.max((Math.min((Math.round(-0) | 0), (x | 0)) >>> 0), ((Math.min((Math.acos(Math.fround(x)) | 0), (( + ( + ( + y))) | 0)) | 0) / (y >>> 0))) >>> 0) - (Math.sinh(Math.fround((Math.min(y, x) >>> 0))) % ( + Math.sign(( + Number.MIN_SAFE_INTEGER))))) >>> 0), (Math.min(((Math.sin(y) & Math.fround((x || ( + -Number.MIN_SAFE_INTEGER)))) >>> 0), Math.pow(Math.fround(( - Math.fround(( ! ( + y))))), (mathy2((((Math.tan(x) - ( ~ y)) | 0) >>> 0), (y >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-0x080000001, 1, -(2**53-2), -(2**53), 1/0, 0x080000001, 0x080000000, 0, 0x100000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -0x080000000, 42, -0x100000001, 0x100000000, 0/0, Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -0, 1.7976931348623157e308, Math.PI, -1/0, 0.000000000000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=230; tryItOut("\"use strict\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-248247344*/count=231; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.clz32(((( ~ y) ? Math.tan(Number.MIN_SAFE_INTEGER) : Math.atan2(Math.fround(y), (y / y))) | 0))) != Math.fround(((y * Math.max(( + Math.hypot(-Number.MAX_VALUE, y)), Math.min(x, y))) || Math.fround((Math.fround((Math.min((((((((y >>> 0) && (-0 >>> 0)) >>> 0) >>> 0) << (Math.log1p(y) >>> 0)) >>> 0) | 0), (Math.fround(Math.imul(Math.fround(-0x100000000), (( + -0x080000000) !== Math.fround(x)))) | 0)) | 0)) || Math.fround(x))))))); }); testMathyFunction(mathy4, [-1/0, -Number.MAX_VALUE, 42, -Number.MIN_VALUE, 0.000000000000001, -(2**53), 2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, -0x100000001, Number.MIN_VALUE, 0x080000001, -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 2**53, 0x080000000, -(2**53+2), -0x080000000, 0x0ffffffff, 0/0, -0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0x07fffffff, 0x07fffffff, 1/0]); ");
/*fuzzSeed-248247344*/count=232; tryItOut("mathy1 = (function(x, y) { return (((( ! Math.fround(Math.imul((Math.fround(( ! y)) | 0), Math.imul(( + Math.round(( + Math.imul(( + (x >> Math.fround(0))), x)))), Math.log10((Math.fround(( - y)) >>> 0)))))) | 0) | (Math.max((( + ( + ( + (( + (mathy0(y, y) >>> 0)) >>> 0)))) | 0), Math.ceil((Math.cosh(Math.fround(( ! ( + x)))) | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [0x07fffffff, -0x100000000, -0x100000001, -0x080000000, 1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -(2**53-2), 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 2**53, -0, 0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x100000000, Math.PI, -Number.MAX_VALUE, -1/0, 0/0, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, 0x100000001, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-248247344*/count=233; tryItOut("\"use asm\"; e1.delete(this.g0);");
/*fuzzSeed-248247344*/count=234; tryItOut("\"use strict\"; function shapeyConstructor(fmgplp){return this; }/*tLoopC*/for (let x of /*MARR*/[ /x/g ,  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), (-1/0),  /x/g , (-1/0), (-1/0), new Number(1.5), (-1/0), new Number(1.5),  /x/g ,  /x/g , (-1/0),  /x/g , (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1.5),  /x/g , new Number(1.5),  /x/g ,  /x/g , (-1/0),  /x/g ,  /x/g , (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1.5), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1.5), (-1/0),  /x/g , (-1/0),  /x/g ,  /x/g ,  /x/g , new Number(1.5), new Number(1.5),  /x/g , (-1/0), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), (-1/0),  /x/g , (-1/0), new Number(1.5), (-1/0), new Number(1.5), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (-1/0),  /x/g , new Number(1.5),  /x/g , (-1/0),  /x/g , (-1/0), (-1/0), new Number(1.5), (-1/0), (-1/0), new Number(1.5), new Number(1.5), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1.5),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (-1/0), (-1/0), (-1/0),  /x/g ,  /x/g ,  /x/g , (-1/0), (-1/0),  /x/g , (-1/0), (-1/0), (-1/0),  /x/g , (-1/0), (-1/0), (-1/0),  /x/g , (-1/0), (-1/0), new Number(1.5), new Number(1.5),  /x/g ,  /x/g ,  /x/g , (-1/0), new Number(1.5),  /x/g ,  /x/g , new Number(1.5), (-1/0), new Number(1.5), (-1/0), (-1/0),  /x/g , new Number(1.5),  /x/g ,  /x/g ,  /x/g , (-1/0),  /x/g , new Number(1.5), new Number(1.5),  /x/g ,  /x/g , new Number(1.5), new Number(1.5), (-1/0), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), (-1/0), new Number(1.5),  /x/g , (-1/0), new Number(1.5), new Number(1.5), (-1/0), new Number(1.5), (-1/0),  /x/g , new Number(1.5),  /x/g , new Number(1.5), (-1/0),  /x/g ,  /x/g , (-1/0), new Number(1.5), new Number(1.5), (-1/0), (-1/0), (-1/0), new Number(1.5)]) { try{let gokgfp = new shapeyConstructor(x); print('EETT'); Array.prototype.unshift.apply(a2, []);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-248247344*/count=235; tryItOut("e0.add(o1);/*iii*/t2 = new Int8Array(t0);/*hhh*/function xogflo(window, {}, ...\u3056){print(delete x.\u0009w);}");
/*fuzzSeed-248247344*/count=236; tryItOut("mathy5 = (function(x, y) { return mathy0(Math.fround((Math.sinh(( ! ( - (mathy0(Math.fround(y), -(2**53+2)) ? x : -Number.MIN_VALUE)))) >>> 0)), Math.sqrt(( ! ((Math.atan2(y, ( + Math.pow(( + x), x))) + (( ~ (Math.log2((x >>> 0)) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [0.000000000000001, -0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), 0/0, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, 1, -(2**53+2), 0x080000000, 0, -0x080000001, Math.PI, 0x080000001, -1/0, 42, 0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0x07fffffff, 2**53, -0x07fffffff, -0]); ");
/*fuzzSeed-248247344*/count=237; tryItOut("with({d: new RegExp(\"(\\\\2)[^]((?!\\\\1))\", \"yim\")}){o1.v2 = Object.prototype.isPrototypeOf.call(h2, i0); }");
/*fuzzSeed-248247344*/count=238; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=239; tryItOut("i2.next();");
/*fuzzSeed-248247344*/count=240; tryItOut("\"use strict\"; \"use asm\"; { void 0; void relazifyFunctions(this); } a2.sort((function() { try { e2.__proto__ = this.o0.o0; } catch(e0) { } try { g0.o2.o0 + i2; } catch(e1) { } try { (x = Proxy.createFunction(({/*TOODEEP*/})(undefined), Proxy.revocable)); } catch(e2) { } g2.v1 = (m1 instanceof t2); throw f0; }));");
/*fuzzSeed-248247344*/count=241; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=242; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + (Math.imul(Math.sin((Math.cbrt((mathy2((( + Math.cosh(y)) - x), Math.asin(( + x))) | 0)) | 0)), ( + Math.ceil((Math.fround(y) != ((x <= Math.PI) !== (x | 0)))))) | 0)); }); testMathyFunction(mathy3, [-0x080000000, 0x100000001, 2**53+2, 0.000000000000001, 0x100000000, 42, -Number.MIN_VALUE, -0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 1.7976931348623157e308, 1, 0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x100000000, 2**53-2, Number.MAX_VALUE, 0x080000000, 0x080000001, -1/0, 0/0, -(2**53+2), 0, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -(2**53), Math.PI, -0]); ");
/*fuzzSeed-248247344*/count=243; tryItOut("mathy1 = (function(x, y) { return (( - (Math.max(Math.max(x, Math.acos(x)), ((y ? (Math.fround((x % (0x0ffffffff | 0))) == (( ~ Math.fround(x)) | 0)) : ((y ? Math.fround(( - Math.fround(y))) : -0x100000000) >>> 0)) >>> ( + Math.imul(( + x), ( + Math.expm1(( + Math.exp(x)))))))) | 0)) >>> 0); }); testMathyFunction(mathy1, [-0x080000001, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, -0, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53), 0x080000000, 2**53, 0.000000000000001, -1/0, 0x0ffffffff, -0x100000001, 2**53+2, -0x07fffffff, 0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -0x0ffffffff, 0, -0x080000000, Number.MIN_VALUE, 42, -0x100000000, -(2**53-2), -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=244; tryItOut("/*RXUB*/var r = r1; var s = x; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=245; tryItOut("\"use strict\"; /*vLoop*/for (oboyho = 0; oboyho < 70; this, ++oboyho) { const b = oboyho;  /x/g ; } ");
/*fuzzSeed-248247344*/count=246; tryItOut("mathy0 = (function(x, y) { return ( ! Math.cosh(Math.sin(( - Math.min(y, (x | 0)))))); }); testMathyFunction(mathy0, [2**53-2, Number.MAX_SAFE_INTEGER, 1/0, 0/0, 0.000000000000001, 1, 0x080000000, Number.MIN_VALUE, -0x100000000, -0x07fffffff, -0, 0x100000000, -0x080000001, -0x0ffffffff, -0x100000001, 0x07fffffff, -Number.MIN_VALUE, 2**53+2, Math.PI, 2**53, 42, 0x100000001, 1.7976931348623157e308, -1/0, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, 0x0ffffffff, 0, -0x080000000, 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=247; tryItOut("\"use strict\"; s0 = '';");
/*fuzzSeed-248247344*/count=248; tryItOut("var r0 = x / x; var r1 = r0 + x; var r2 = x ^ r1; r1 = r1 ^ x; r1 = r2 + x; var r3 = r0 - 0; var r4 = r1 % 3; var r5 = 6 - 2; var r6 = r3 / r5; var r7 = r3 - 2; print(r1); ");
/*fuzzSeed-248247344*/count=249; tryItOut("x;\na1[16];\n");
/*fuzzSeed-248247344*/count=250; tryItOut("if(x) { if (x) a0.splice(); else {throw x;const flgyou, x, mitert, d, zruuby, d, d, NaN;print(this); }}L:switch(true) { default: break;  }");
/*fuzzSeed-248247344*/count=251; tryItOut("if(true) v0 = a2.length; else  if (eval <<= e)  /x/g ;h0.toSource = (function mcc_() { var cmsrym = 0; return function() { ++cmsrym; f1(/*ICCD*/cmsrym % 11 == 6);};})();");
/*fuzzSeed-248247344*/count=252; tryItOut("if(false) {g0.a2.sort((function() { try { p0.toSource = (function mcc_() { var jvucsw = 0; return function() { ++jvucsw; o1.f1(/*ICCD*/jvucsw % 5 == 3);};})(); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(e1, s1); } catch(e1) { } m0 = t2[14]; return m2; }), h2, (4277), h1);print(\u3056--); } else  if (+x) p0.toSource = f2; else nulsbz");
/*fuzzSeed-248247344*/count=253; tryItOut("\"use strict\"; for (var p in t0) { try { Array.prototype.shift.call(a1); } catch(e0) { } v0 + ''; }");
/*fuzzSeed-248247344*/count=254; tryItOut("mathy0 = (function(x, y) { return ( + (( ~ Math.atan2(( + Math.max(Math.pow((( ~ x) >>> 0), (y >>> 0)), (( + (x >>> 0)) >>> 0))), ((x | 0) | Math.fround((Math.acos(0/0) && (( + x) ? ( + y) : ((x < -Number.MAX_SAFE_INTEGER) | 0))))))) <= (( + (( + ((Math.max(-0x080000000, ( + x)) | 0) != Math.fround((Math.fround(Math.atanh(Math.fround((Math.atan((x | 0)) | 0)))) << Math.fround((Math.atan2((y | 0), (x | 0)) | 0)))))) <= ( + (Math.pow((objectEmulatingUndefined() | 0), ((y !== Math.fround(Math.sign(x))) | 0)) | 0)))) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void version(185)), (void version(185)), (void version(185)), (void version(185)), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), (void version(185)), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined(), (void version(185)), objectEmulatingUndefined()]); ");
/*fuzzSeed-248247344*/count=255; tryItOut("mathy3 = (function(x, y) { return (Math.sin(((( + ( + (( + Math.fround(Math.sqrt(Math.fround(( ! ( ! x)))))) <= ( + Math.fround(Math.log10(x)))))) * ( + (Math.atan2((( + ( ! Math.fround(Math.imul(Math.fround(x), Math.fround(y))))) >>> 0), (y | 0)) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=256; tryItOut("testMathyFunction(mathy2, /*MARR*/[Infinity, (0/0), -Number.MIN_SAFE_INTEGER, (0/0), Infinity, Infinity, (0/0), (0/0), Infinity, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Infinity, Infinity, (0/0), Infinity, (0/0), -Number.MIN_SAFE_INTEGER, Infinity, Infinity, -Number.MIN_SAFE_INTEGER, new Number(1.5), Infinity, -Number.MIN_SAFE_INTEGER, (0/0), -Number.MIN_SAFE_INTEGER, new Number(1.5), -Number.MIN_SAFE_INTEGER, Infinity, Infinity, (0/0), Infinity, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Infinity, new Number(1.5), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, -Number.MIN_SAFE_INTEGER, Infinity, Infinity, -Number.MIN_SAFE_INTEGER, new Number(1.5), (0/0), (0/0), new Number(1.5), new Number(1.5), -Number.MIN_SAFE_INTEGER, Infinity, (0/0), Infinity, new Number(1.5), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Infinity, new Number(1.5), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, new Number(1.5), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Number(1.5), (0/0), -Number.MIN_SAFE_INTEGER, (0/0), Infinity, Infinity, -Number.MIN_SAFE_INTEGER, Infinity, -Number.MIN_SAFE_INTEGER, Infinity, new Number(1.5), (0/0), Infinity, Infinity, Infinity, (0/0), (0/0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Infinity, Infinity, new Number(1.5), Infinity, new Number(1.5), (0/0), Infinity, new Number(1.5), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Number(1.5), Infinity, (0/0), new Number(1.5), new Number(1.5), (0/0), Infinity, Infinity, new Number(1.5), Infinity, Infinity, -Number.MIN_SAFE_INTEGER, new Number(1.5), Infinity, Infinity, (0/0), -Number.MIN_SAFE_INTEGER, Infinity, -Number.MIN_SAFE_INTEGER, Infinity, -Number.MIN_SAFE_INTEGER, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), Infinity, Infinity, Infinity, Infinity, Infinity, new Number(1.5), -Number.MIN_SAFE_INTEGER, Infinity, Infinity, new Number(1.5), new Number(1.5), new Number(1.5), -Number.MIN_SAFE_INTEGER, new Number(1.5), new Number(1.5), (0/0), (0/0), Infinity, -Number.MIN_SAFE_INTEGER, Infinity, Infinity, Infinity, new Number(1.5), Infinity, Infinity, new Number(1.5), (0/0), (0/0), (0/0), -Number.MIN_SAFE_INTEGER, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, (0/0), (0/0), (0/0), -Number.MIN_SAFE_INTEGER, new Number(1.5), (0/0), -Number.MIN_SAFE_INTEGER, (0/0), Infinity, (0/0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, new Number(1.5), -Number.MIN_SAFE_INTEGER, (0/0), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity]); ");
/*fuzzSeed-248247344*/count=257; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i0 = (i0);\n    return +((-4.835703278458517e+24));\n    i0 = (i0);\n    {\n      {\n        (Float32ArrayView[1]) = ((-6.044629098073146e+23));\n      }\n    }\n    i0 = (!((0x0)));\n    return +((15.0));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use asm\"; var sorinr = new SharedArrayBuffer(305562747.5, new RegExp(\"(.(?=\\\\w\\\\B|[^\\\\b-\\\\\\u8599\\u0019-\\u00d6\\\\cB-\\\\x57][\\\\f-(\\\\w\\\\cX-~\\\\s]|.{0}))?\", \"yi\")); (arguments.callee)(); })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=258; tryItOut("\"use strict\"; v1 = new Number(0);");
/*fuzzSeed-248247344*/count=259; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.atan2(Math.cos(mathy1((-Number.MIN_SAFE_INTEGER && x), y)), ( + Math.imul(Math.fround(Math.atan2(Math.fround(Math.sign(Math.fround(mathy1(y, x)))), Math.fround(Math.hypot((Math.atanh(x) + Math.max(y, x)), x)))), ( + Math.max(( + mathy2(y, Number.MAX_VALUE)), ( + (y % ( ! ( + 0.000000000000001))))))))); }); ");
/*fuzzSeed-248247344*/count=260; tryItOut("\"use strict\"; /*bLoop*/for (let fktgld = 0; fktgld < 80; ++fktgld) { if (fktgld % 6 == 0) { /*ADP-3*/Object.defineProperty(o1.a1, o2.g0.v0, { configurable: (x % 23 != 19), enumerable: false, writable: (x % 24 != 21), value: o0.o0 }); } else { g0.v2 = (o2.s0 instanceof b2); }  } ");
/*fuzzSeed-248247344*/count=261; tryItOut("\"use strict\"; a2 = a1.concat(a0, t2, t2);");
/*fuzzSeed-248247344*/count=262; tryItOut("i1.next();");
/*fuzzSeed-248247344*/count=263; tryItOut("o0 = new Object;");
/*fuzzSeed-248247344*/count=264; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x100000001, 0.000000000000001, Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, 2**53, 42, -0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -(2**53-2), -1/0, 0x0ffffffff, 0x100000000, 0/0, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, 1/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, -0, -0x080000001, 2**53-2, 0x07fffffff, -(2**53), -Number.MIN_VALUE, 2**53+2, 0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-248247344*/count=265; tryItOut("if(false) {(typeof ((function factorial(cbphlu) { ; if (cbphlu == 0) { ; return 1; } ; return cbphlu * factorial(cbphlu - 1);  })(1))); }");
/*fuzzSeed-248247344*/count=266; tryItOut("\"use strict\"; {t1 + ''; }a2.forEach((function() { try { g2.v0 = g1.eval(\"/* no regression tests found */\"); } catch(e0) { } a1.splice(NaN, ({valueOf: function() { /*RXUB*/var r = /(?:\\1(?!(?![]){2,5})*?\\u00B6(?=(?!(?!$|.)))?|\\b)/gy; var s = \"\\u00b6\\n\\n\\n\\ubb25\\u00b6\\n\\n\\n\\ubb25\\u00b6\\n\\n\\n\\ubb25\"; print(r.test(s)); return 10; }})); return o2; }), e1, (eval(\"mathy2 = (function(x, y) { return Math.min((Math.pow(( - ((y | 0) === ( + (Math.sinh(y) | 0)))), ((Math.fround(mathy1(((x == ( + 2**53+2)) | 0), ( + (( + x) ? y : ( + y))))) >> Math.fround((( + (Math.exp((((x | Math.round(x)) | 0) | 0)) | 0)) << ( + Number.MIN_SAFE_INTEGER)))) | 0)) >>> 0), (( + (((( + x) & x) === Math.fround(x)) / Math.fround((((Math.atanh((y | 0)) | 0) - Math.fround(Math.abs(Math.fround((( + (-0x080000000 | 0)) | 0))))) | 0)))) - ( - Math.pow(mathy0(x, ((Math.fround(x) + Math.fround(y)) >>> 0)), Math.round(Math.fround(( + ( - x)))))))); }); testMathyFunction(mathy2, [-1/0, 42, -0x100000001, Math.PI, -(2**53+2), -Number.MIN_VALUE, 1, 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 0.000000000000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x080000001, -(2**53), 0x100000000, 2**53, Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, Number.MAX_VALUE, -0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, -0x100000000, -0x080000000, 0/0, 0]); \")));");
/*fuzzSeed-248247344*/count=267; tryItOut("\"use strict\"; { void 0; setIonCheckGraphCoherency(false); } /*ODP-2*/Object.defineProperty(b0, \"__parent__\", { configurable: false, enumerable: false, get: (function() { try { Object.prototype.unwatch.call(m1, \"map\"); } catch(e0) { } Object.preventExtensions(m2); return i0; }), set: (function(j) { if (j) { try { Array.prototype.sort.apply(a1, [(function() { for (var j=0;j<14;++j) { f2(j%2==1); } })]); } catch(e0) { } try { (void schedulegc(g0)); } catch(e1) { } try { this.s2 = ''; } catch(e2) { } v0 = evaluate(\"-0.427\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 14 != 11), noScriptRval: false, sourceIsLazy: (x % 3 != 1), catchTermination: (x % 15 == 7), sourceMapURL: s2 })); } else { try { var g0.h0 = ({getOwnPropertyDescriptor: function(name) { this.a0[3] = \"\\u3C43\";; var desc = Object.getOwnPropertyDescriptor(m2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { a1 = Array.prototype.filter.apply(a1, [f0, o2]);; var desc = Object.getPropertyDescriptor(m2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0 = [];; Object.defineProperty(m2, name, desc); }, getOwnPropertyNames: function() { Array.prototype.push.apply(this.a1, [ \"\" , g0, g2.o0, m0, o1, a0, m2]);; return Object.getOwnPropertyNames(m2); }, delete: function(name) { g2.m1.__proto__ = t0;; return delete m2[name]; }, fix: function() { o1.h0.get = (function() { try { v1 = (b2 instanceof s2); } catch(e0) { } try { a1 = Array.prototype.filter.apply(a2, [(function() { try { i2 + ''; } catch(e0) { } try { m1.has(a0); } catch(e1) { } try { v1 = NaN; } catch(e2) { } v1 = g1.runOffThreadScript(); return this.h1; }), a0, false, p1, o2, g0.a2, g0.e2]); } catch(e1) { } try { e2.toString = (function mcc_() { var zlynym = 0; return function() { ++zlynym; if (true) { dumpln('hit!'); try { Array.prototype.sort.apply(a2, []); } catch(e0) { } try { m2.has(m1); } catch(e1) { } h1.hasOwn = (function(j) { if (j) { try { /*MXX1*/o1 = g1.Uint16Array.BYTES_PER_ELEMENT; } catch(e0) { } try { e2 + ''; } catch(e1) { } i0.send(a1); } else { try { m0.delete(e0); } catch(e0) { } try { h2.defineProperty = (function() { try { for (var p in a2) { try { a2.shift(v2); } catch(e0) { } v2 = new Number(m0); } } catch(e0) { } try { Array.prototype.pop.call(a1, p2); } catch(e1) { } try { v2 = (i1 instanceof g0.o1.o0.o2); } catch(e2) { } e2.add(g0.m0); return m0; }); } catch(e1) { } a2.forEach(o1); } }); } else { dumpln('miss!'); try { m1 = m2.get(h0); } catch(e0) { } try { a1.toSource = (function() { for (var j=0;j<24;++j) { this.f2(j%3==1); } }); } catch(e1) { } try { print(uneval(v2)); } catch(e2) { } v2 = evalcx(\"this;\", g0); } };})(); } catch(e2) { } a0.unshift(this.e2, o0.p1, e2, m1, o1); return g2; });; if (Object.isFrozen(m2)) { return Object.getOwnProperties(m2); } }, has: function(name) { this.t2[2] = m1;; return name in m2; }, hasOwn: function(name) { Object.preventExtensions(p1);; return Object.prototype.hasOwnProperty.call(m2, name); }, get: function(receiver, name) { /*ADP-3*/Object.defineProperty(a2, 2, { configurable: (x % 6 == 4), enumerable: true, writable: false, value: this.i2 });; return m2[name]; }, set: function(receiver, name, val) { this.s0 += 'x';; m2[name] = val; return true; }, iterate: function() { t1 = t1.subarray(6, 13);; return (function() { for (var name in m2) { yield name; } })(); }, enumerate: function() { v1 = evalcx(\"function f2(s1) x\", g0);; var result = []; for (var name in m2) { result.push(name); }; return result; }, keys: function() { g0 + h0;; return Object.keys(m2); } }); } catch(e0) { } e0.has(s1); } }) });");
/*fuzzSeed-248247344*/count=268; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    return (((i1)+(((-(i1)) >> ((i1))))+((/*FFI*/ff((((((0x6048bfb1) ? (0xe6531eeb) : (0xde275192))) << ((i1)+(/*FFI*/ff(((562949953421313.0)), ((-36893488147419103000.0)), ((-2097153.0)))|0)))), ((((0x9e4d0580)*-0xfffff) >> ((0x3e73bd1a) / (0x76d9a097)))), ((d0)), ((+(0x1ff6af22))), ((-590295810358705700000.0)), ((-1.001953125)), ((4.0)), ((2251799813685248.0)), ((-512.0)), ((2.4178516392292583e+24)), ((-134217729.0)), ((-1.888946593147858e+22)), ((18446744073709552000.0)), ((295147905179352830000.0)), ((8796093022207.0)), ((-144115188075855870.0)), ((4.835703278458517e+24)), ((-36893488147419103000.0)), ((-1.0)), ((-268435457.0)), ((-1125899906842625.0)), ((255.0)), ((257.0)), ((2147483649.0)), ((-8193.0)), ((-2.4178516392292583e+24)), ((17.0)))|0) ? ((((-0x8000000)-(0xfa7b2a0a))>>>((0xf92a0ed4)-(0x177bfc67))) <= (((0xf05437c8)+(-0x8000000)-(0xbf6ce28c))>>>(((0x0))))) : (/*FFI*/ff(((1.25)), (), ((d0)), ((+(0x20d4a6c7))), ((137438953471.0)), ((8193.0)), ((8388609.0)), ((-576460752303423500.0)), ((-4.722366482869645e+21)), ((-274877906945.0)), ((-32769.0)), ((17.0)), ((-4398046511103.0)), ((-1048575.0)), ((-67108865.0)), ((-281474976710657.0)), ((4.835703278458517e+24)), ((536870913.0)), ((-18014398509481984.0)), ((-4097.0)), ((73786976294838210000.0)), ((0.5)), ((-65.0)), ((5.0)), ((-3.094850098213451e+26)), ((4194305.0)), ((8796093022209.0)), ((70368744177663.0)), ((8796093022209.0)), ((-147573952589676410000.0)), ((33554433.0)), ((-4294967297.0)), ((-17592186044417.0)), ((67108865.0)), ((-3.094850098213451e+26)), ((-536870913.0)), ((1.0078125)), ((-70368744177663.0)), ((67108865.0)))|0))))|0;\n  }\n  return f; })(this, {ff: () =>  { return x } }, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, 0, 1/0, 1, 2**53, -0x100000001, -(2**53), 42, 0.000000000000001, Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0x100000000, 1.7976931348623157e308, -0, -0x080000001, 0x080000000, 0x080000001, -1/0, 2**53-2, -Number.MAX_VALUE, 0x100000001, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=269; tryItOut("{ void 0; void relazifyFunctions(this); } print((this.throw( '' )));");
/*fuzzSeed-248247344*/count=270; tryItOut("mathy3 = (function(x, y) { return Math.max(Math.fround(( + (( + (Math.atan(y) == (( - Math.fround(( + ( - x)))) >>> 0))) , ( + (( + y) !== ( + (Math.hypot(Math.imul(0x100000000, Math.min(Math.fround(x), Math.fround(y))), x) != Math.fround(-Number.MIN_SAFE_INTEGER)))))))), Math.fround((((Math.pow((-Number.MIN_VALUE | 0), Math.pow(-Number.MIN_VALUE, (Math.hypot(x, 0x07fffffff) <= x))) >>> 0) <= (Math.atan2(mathy2((Math.imul((y >>> 0), (x >>> 0)) >>> 0), (Math.fround(Math.hypot(Math.fround(Math.acosh(-0x07fffffff)), Math.fround(x))) >>> 0)), y) | 0)) >>> 0))); }); ");
/*fuzzSeed-248247344*/count=271; tryItOut("Object.freeze(b2);");
/*fuzzSeed-248247344*/count=272; tryItOut("const x, x = arguments.callee.arguments = ((makeFinalizeObserver('nursery'))), pfnfcq, nfomui, e = -9;/*vLoop*/for (var pqqiua = 0; pqqiua < 25; ++pqqiua, \u000cyield x) { x = pqqiua; /*RXUB*/var r = r0; var s = \"00\"; print(r.exec(s));  } ");
/*fuzzSeed-248247344*/count=273; tryItOut("h1.valueOf = (function() { for (var j=0;j<22;++j) { this.f2(j%3==1); } });");
/*fuzzSeed-248247344*/count=274; tryItOut("\"use strict\"; Array.prototype.unshift.call(a0, o0, t0, g1, b0, this.m2, eval(\"mathy2 = (function(x, y) { return (Math.exp((( - (( - ( + Math.log1p(( + y)))) | 0)) * Math.fround(( ! ( + ( + ( + ( + mathy1(x, ( + x)))))))))) == (Math.min(x, Math.max(y, ( + ( + (( + x) ? y : ( + x)))))) | Math.pow(((((Math.asinh((y | 0)) | 0) ? y : -0x100000000) && ((2**53+2 !== ((1.7976931348623157e308 | 0) & 0/0)) | 0)) ? Math.tan(x) : (mathy0(-Number.MIN_SAFE_INTEGER, ( + y)) <= Math.tan(-0x100000001))), ( + (( - -0) || (( - Math.fround(Number.MAX_VALUE)) >>> 0)))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 1/0, -0, 0x0ffffffff, 2**53, 0x07fffffff, -0x100000001, 0x100000000, -0x100000000, 42, -1/0, -0x0ffffffff, -0x080000000, 0/0, 1, -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, -(2**53-2), 2**53+2, 0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -0x07fffffff, -0x080000001]); \", x = Proxy.createFunction((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { var r0 = a15 + a18; var r1 = a5 ^ a19; var r2 = 8 + a11; var r3 = a6 * a4; var r4 = a0 / 7; var r5 = 7 % 9; a12 = a17 & 9; print(r2); var r6 = 4 | a13; var r7 = 5 | 6; a19 = a5 / a3; var r8 = 7 + r2; var r9 = 0 | x; a5 = 3 | 4; var r10 = 0 | a12; r10 = r8 + r4; r5 = 8 ^ a14; r5 = 4 + r5; var r11 = a10 + a19; var r12 = a4 & a18; var r13 = a6 * 1; r2 = r12 ^ r13; var r14 = 4 + r3; var r15 = r11 * 3; print(r1); a13 = a18 * 4; var r16 = a8 / r3; var r17 = a0 * a5; var r18 = 5 + r16; var r19 = r13 ^ 7; var r20 = 8 * a12; print(x); var r21 = 7 ^ r18; var r22 = 5 - r12; print(r5); var r23 = a15 ^ a11; var r24 = r6 & r13; var r25 = 0 + a11; var r26 = 7 * 6; var r27 = a12 + r26; r8 = x & 2; r2 = r15 ^ r6; var r28 = r23 * r6; var r29 = r7 + r1; var r30 = r14 + 2; var r31 = r11 ^ a14; var r32 = 2 & a10; a15 = 6 + 8; var r33 = r19 - a15; var r34 = r23 / r11; var r35 = r23 % r28; var r36 = r9 * a10; r7 = r15 & r28; var r37 = r28 & 6; return a14; }), new Function, (function(x, y) { return ( + Math.atanh(( + y))); })) >>= /*MARR*/[0x07fffffff, [1], {x:3}, {x:3}, 0x07fffffff, x, [1], {x:3}, [1], 0x07fffffff, {x:3}, [1], 0x07fffffff, x, x, x, {x:3}, 0x07fffffff, {x:3}, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, 0x07fffffff, 0x07fffffff, {x:3}, [1], [1], 0x07fffffff, 0x07fffffff, [1], {x:3}, x, x, [1], [1], [1], 0x07fffffff, 0x07fffffff, 0x07fffffff, {x:3}, x, {x:3}, x, 0x07fffffff, {x:3}, x, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], x, x, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, x, 0x07fffffff, [1], {x:3}, {x:3}, [1], [1], {x:3}, {x:3}, x, x, {x:3}, [1], [1], {x:3}, {x:3}, x, {x:3}, [1], [1], 0x07fffffff, x, 0x07fffffff, {x:3}, x, {x:3}, {x:3}, [1], [1], x, 0x07fffffff, x, {x:3}, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, x, 0x07fffffff, 0x07fffffff, x, [1], {x:3}, 0x07fffffff, 0x07fffffff].sort(function(q) { return q; },  \"\" )), g1.e0);");
/*fuzzSeed-248247344*/count=275; tryItOut("mathy2 = (function(x, y) { return (Math.imul((( - (Math.fround(( ! Math.fround(( ~ mathy0(x, x))))) != x)) >>> 0), (Math.fround((Math.fround(Math.log(Math.clz32((Math.sign(1) | 0)))) ? Math.fround((Math.pow(y, (( + ( + ((x | 0) && (x | 0)))) >>> 0)) >>> 0)) : Math.fround((( + ((((-0x100000001 | 0) ? ((Math.hypot((x >>> 0), (x >>> 0)) >>> 0) | 0) : (y | 0)) | 0) ** -0x100000001)) == mathy1(x, Math.fround(Math.max(Math.fround(y), (x | 0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [(new Boolean(false)), '0', 0, (new Number(0)), (new Number(-0)), /0/, (function(){return 0;}), false, '', [], (new Boolean(true)), [0], -0, '\\0', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), 0.1, (new String('')), undefined, objectEmulatingUndefined(), NaN, ({valueOf:function(){return 0;}}), '/0/', true, null, 1]); ");
/*fuzzSeed-248247344*/count=276; tryItOut("/*oLoop*/for (var irrbfh = 0; irrbfh < 34; ++irrbfh) { (timeout(1800)); } ");
/*fuzzSeed-248247344*/count=277; tryItOut("mathy4 = (function(x, y) { return ( ~ ( + Math.pow(( + Math.clz32(Math.fround(( - x)))), y))); }); testMathyFunction(mathy4, [0, -(2**53-2), 0x100000001, 0x07fffffff, -0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, 0x080000000, 1, 2**53+2, -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, 2**53, -0x100000001, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0x100000000, 0/0, Math.PI, -0x080000001, 0x0ffffffff, 42, 2**53-2, Number.MAX_VALUE, -1/0, -0]); ");
/*fuzzSeed-248247344*/count=278; tryItOut("\"use strict\"; e1.add(o0.p2);");
/*fuzzSeed-248247344*/count=279; tryItOut("e1.has(/*UUV2*/(\u3056.log2 = \u3056.set));");
/*fuzzSeed-248247344*/count=280; tryItOut("i0.send(o2);function x(window, (x), ...z)\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+atan2(((+abs(((-((((((-257.0)) / ((d1)))) * ((((+((-4398046511105.0)))) % ((d1))))))))))), (Math.max(x,  /x/g )))));\n  }\n  return f;function shapeyConstructor(axnnel){this[(function ([y]) { })()] = true;if (\"\\uF7FB\") delete this[w];return this; }/*tLoopC*/for (let a of encodeURIComponent) { try{let hxvztc = shapeyConstructor(a); print('EETT'); o0.g2.a1 = t1[6];}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-248247344*/count=281; tryItOut("mathy3 = (function(x, y) { return ( + (( + ((( - ( + ( ~ x))) >>> 0) | Math.fround(Math.ceil(( + mathy0(( + y), ( + x))))))) << ( + Math.atan2((((( + Math.pow((0/0 >>> 0), Math.fround(y))) >>> 0) ? ( + (Math.abs((y >>> 0)) >>> 0)) : ((Math.fround(( - y)) | (Math.hypot(x, (y >>> 0)) >>> 0)) >>> 0)) >>> 0), (Math.fround(mathy0(y, x)) ^ (Math.max(Math.fround((Math.fround(Math.hypot(y, x)) >>> ( + x))), x) | 0)))))); }); ");
/*fuzzSeed-248247344*/count=282; tryItOut("mathy0 = (function(x, y) { return ( + ((Math.pow((Math.fround(( ~ Math.fround(Math.atanh(((( + y) ? ( + y) : (y >>> 0)) | 0))))) | 0), (Math.fround(Math.asin(Math.cos((Math.min((y >>> 0), (y | 0)) | 0)))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[arguments, new Number(1.5), arguments, [], [], arguments, new Number(1.5), new Number(1.5), [], arguments, [], arguments, [], arguments, arguments, new Number(1.5), arguments, arguments, [], [], arguments, arguments, arguments, new Number(1.5)]); ");
/*fuzzSeed-248247344*/count=283; tryItOut("let (\u3056 = intern( /x/  ? new RegExp(\"(?:(?:\\\\1*?){0}(?=(?!..?|(N)|\\\\b)))\", \"y\") : [,]), wbhcba, c, y, x, \u3056, x, tnfnox, d) { ghdzjz();/*hhh*/function ghdzjz(...x){v0 = (e2 instanceof o0.b0);} }");
/*fuzzSeed-248247344*/count=284; tryItOut("e0.delete(this.m2);");
/*fuzzSeed-248247344*/count=285; tryItOut("\"use strict\"; t0.set(a0, 3);");
/*fuzzSeed-248247344*/count=286; tryItOut("\"use strict\"; v1 = g1.runOffThreadScript();");
/*fuzzSeed-248247344*/count=287; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=288; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"(?:$(?!(?!\\\\B+)|\\\\b|\\\\D|[^]*|[^]+?{0,1}))*\", \"yim\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-248247344*/count=289; tryItOut("this.t1 = new Float32Array(a1);");
/*fuzzSeed-248247344*/count=290; tryItOut("mathy3 = (function(x, y) { return (Math.clz32((( + ( + Math.fround(( ~ Math.fround(( ! ( + ( + y)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [2**53-2, 0x080000001, -0x100000001, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, -1/0, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, Math.PI, -(2**53-2), 0/0, 0x080000000, 1, 42, -(2**53), 0, 1/0, -0x0ffffffff, 2**53, -0, 0x100000000, -0x080000000, 0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=291; tryItOut("x = o1.f2;");
/*fuzzSeed-248247344*/count=292; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy2((Math.asin((y | (Math.imul((Math.pow(y, x) | 0), ((Math.atan2((Math.PI | 0), x) | 0) | 0)) | 0))) | 0), ((( ~ Math.ceil(mathy1(x, (0x080000001 , y)))) ? (Math.asinh(mathy2(x, ( ~ 1.7976931348623157e308))) | 0) : Math.fround(Math.imul(Math.fround(( ! Math.fround(Math.sinh((-Number.MIN_SAFE_INTEGER | 0))))), Math.fround(( ~ Math.log10((( + y) | 0))))))) >>> 0)); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, Math.PI, -0x100000001, 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, 2**53+2, -0, 0x07fffffff, 0x080000000, -(2**53-2), Number.MAX_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 0x100000001, 0/0, 0x100000000, 0.000000000000001, -0x080000000, 42, -1/0, -Number.MAX_VALUE, 1/0, -(2**53)]); ");
/*fuzzSeed-248247344*/count=293; tryItOut("for(var [w, x] = throw  /x/g  in this) {print(o1.a0); }\no0 + '';\n");
/*fuzzSeed-248247344*/count=294; tryItOut("mathy2 = (function(x, y) { return ( + ((Math.fround(Math.max(Math.fround(y), (Math.fround(( ~ y)) | 0))) >> Math.hypot((Math.fround(( - Math.fround(x))) | 0), (( + (y | 0)) | 0))) <= (( ~ (y | 0)) | 0))); }); testMathyFunction(mathy2, [-(2**53-2), 2**53+2, Number.MAX_VALUE, 0.000000000000001, 0x100000000, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -0, 0x080000000, 2**53, Number.MIN_VALUE, 1/0, 0x080000001, -0x100000001, 1, 0/0, -0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0, -1/0, 0x100000001]); ");
/*fuzzSeed-248247344*/count=295; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -590295810358705700000.0;\n    {\no2.e0.add(f0);    }\n    return +((((((0x6ab6d598) ? ((0x71c2ffda) ? (0xffffffff) : (/*FFI*/ff(((((0x74c1be36)) & ((-0x8000000)))), ((((0x1c3df0b4)) >> ((-0x5c4fe6)))), ((1099511627776.0)), ((-34359738369.0)), ((1.1805916207174113e+21)), ((-295147905179352830000.0)), ((-16777217.0)), ((2097153.0)), ((1.25)), ((-70368744177664.0)), ((-9.44473296573929e+21)), ((129.0)))|0)) : (/*FFI*/ff(((+((((Infinity)) - ((d1)))))), ((x && x)), ((((-0x8000000)-(0xfe2e725a)) | (((-8193.0) > (0.125))))), ((d0)), (( '' )), ((0.0625)), ((33554432.0)), ((2251799813685247.0)), ((16384.0)), ((1.0625)), ((-17.0)), ((-1025.0)), ((4097.0)), ((-3.8685626227668134e+25)), ((288230376151711740.0)), ((-4398046511105.0)), ((-65.0)), ((288230376151711740.0)))|0)))|0)));\n  }\n  return f; })(this, {ff: (uneval(((x.valueOf(\"number\")) || /(?:(([J\\cL\\D][^\\u00c3-\u00d6])*?\\b{2,}))/im)))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=296; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((513.0));\n  }\n  return f; })(this, {ff:  \"\" }, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, 1/0, 0x0ffffffff, 2**53+2, 2**53-2, -0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, 1.7976931348623157e308, -(2**53), -0x100000001, Math.PI, -0x080000001, -1/0, -0x07fffffff, 1, 0x100000001, 0, -Number.MIN_VALUE, 0/0, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -0x080000000, -0]); ");
/*fuzzSeed-248247344*/count=297; tryItOut("L: yield (c = NaN);var c = (4277);");
/*fuzzSeed-248247344*/count=298; tryItOut("\"use strict\"; with(intern(({})))/*RXUB*/var r = /(?:$|(?!(?=\\s)+)\\b{4,}(?=\\1{1,}|\\b+?)|\\B*|(?=(?!\uaa17))*?|[^].+?)/g; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=299; tryItOut("/*ODP-3*/Object.defineProperty(o1.e0, \"max\", { configurable: true, enumerable: false, writable: ({x: function shapeyConstructor(arquqe){for (var ytqfmcicj in this) { }Object.freeze(this);for (var ytqwskejy in this) { }{ for (var p in s0) { try { v1 = (s1 instanceof g2); } catch(e0) { } print([[]]); } } if (x) this[new String(\"13\")] = decodeURIComponent;if (arquqe) this[\"9\"] = new Number(1);this[\"toString\"] = (function(x, y) { \"use strict\"; return 0.000000000000001; });return this; }, x: x }), value: s2 });var b = (4277);");
/*fuzzSeed-248247344*/count=300; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.pow(((Math.min((mathy0(x, ( + Math.pow((y | 0), (y | 0)))) | 0), (Math.pow(Math.exp((( + ( - Number.MAX_VALUE)) | 0)), (( ~ (( + y) << x)) >>> 0)) | 0)) | 0) >>> 0), (( + Math.expm1(((mathy1(x, (Math.imul((x | 0), Math.fround(-Number.MIN_SAFE_INTEGER)) | 0)) >>> 0) - Math.fround(Math.cbrt(Math.pow(y, x)))))) >>> 0)); }); testMathyFunction(mathy2, [0x07fffffff, -(2**53+2), 1/0, -0, 1, 2**53+2, Number.MAX_VALUE, -0x080000000, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 2**53, 0, -(2**53-2), 2**53-2, 0/0, -1/0, -0x080000001, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, Math.PI, 42, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-248247344*/count=301; tryItOut("v1 = evaluate(\"function this.f2(f2)  { a1.valueOf = this.f0; } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: (x % 30 != 17), catchTermination: (x % 3 != 2) }));");
/*fuzzSeed-248247344*/count=302; tryItOut("testMathyFunction(mathy0, [2**53-2, 0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -1/0, -(2**53), -0x080000001, -0, -0x080000000, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 1/0, -Number.MIN_VALUE, 2**53, Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, 0x100000000, -(2**53-2), 2**53+2, 0/0, -Number.MAX_VALUE, 1, 0x080000001, 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-248247344*/count=303; tryItOut("\"use strict\"; v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: x, sourceIsLazy: (x % 2 != 0), catchTermination: (x % 7 != 4), element: this.g2.o1 }));");
/*fuzzSeed-248247344*/count=304; tryItOut("\"use strict\"; var lesvib = new ArrayBuffer(12); var lesvib_0 = new Int32Array(lesvib); print(lesvib_0[0]); lesvib_0[0] = 6; var lesvib_1 = new Int8Array(lesvib); lesvib_1[0] = 8; var lesvib_2 = new Int16Array(lesvib); lesvib_2[0] = -26; var lesvib_3 = new Float32Array(lesvib); var lesvib_4 = new Int32Array(lesvib); var lesvib_5 = new Uint8Array(lesvib); var lesvib_6 = new Uint8Array(lesvib); lesvib_6[0] = -23; print( /x/g );/*MXX3*/g1.WeakMap.prototype.has = g1.WeakMap.prototype.has;print(lesvib_6);null;Object.prototype.unwatch.call(g1.t0, -10);s0 = '';v0 = Object.prototype.isPrototypeOf.call(v2, b2);v0 = g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-248247344*/count=305; tryItOut("");
/*fuzzSeed-248247344*/count=306; tryItOut("mathy2 = (function(x, y) { return (((Math.atan2((mathy1(mathy1(y, Math.fround(y)), Math.log1p(( + x))) >>> 0), Math.fround(( ~ Math.round(y)))) >>> 0) , ( ~ Math.fround(Math.cbrt(x)))) != Math.fround(mathy0(( + ( + (( + Math.fround((x * Math.fround((x != x))))) , ( + Math.hypot(0x0ffffffff, y))))), Math.fround(( + Math.atan2(Math.fround(y), (( - ( + mathy0(y, y))) >>> 0))))))); }); ");
/*fuzzSeed-248247344*/count=307; tryItOut("g1.f2.toString = (function mcc_() { var cleuvl = 0; return function() { ++cleuvl; f2(/*ICCD*/cleuvl % 3 != 1);};})();");
/*fuzzSeed-248247344*/count=308; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((((Math.fround(mathy2(( + (mathy3(Math.fround(2**53), (mathy2((( + Math.fround(Math.pow(Math.fround(y), y))) ? x : x), Math.clz32(y)) | 0)) | 0)), ( + (( + (Math.asin(x) % y)) ? Math.fround((x * (Math.tan(x) ? (1/0 >>> 0) : -Number.MIN_SAFE_INTEGER))) : ( + x))))) | 0) - (((Math.fround((Math.tan(x) % x)) || ((Math.cos(((Math.cos(( + (Math.imul((x | 0), (y | 0)) | 0))) | 0) | 0)) | 0) | 0)) | 0) | 0)) | 0) > (((Math.imul((((y >>> 0) + ( + mathy3(( + ( + (x + ( + y)))), ( + y)))) >>> 0), (( + ( ~ ( + (((y | 0) === x) ** x)))) | 0)) | 0) && ((Math.pow((x | 0), (y | 0)) >>> 0) >>> 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[new String('')]); ");
/*fuzzSeed-248247344*/count=309; tryItOut("mathy5 = (function(x, y) { return ( + mathy2(mathy1((((y != -Number.MIN_VALUE) < y) >= (mathy1((x >>> 0), ((((y >>> 0) % (x >>> 0)) >>> 0) >>> 0)) >>> 0)), (((0 | 0) ? Math.fround(( ! ((Math.sign(1.7976931348623157e308) , y) | 0))) : (y / y)) | 0)), ( + Math.fround((Math.fround(Math.atan2(Math.fround(Math.sqrt(Math.fround(x))), Math.cbrt((mathy4(((Math.fround(x) ? Math.fround(((0.000000000000001 ? y : (0.000000000000001 >>> 0)) >>> 0)) : y) >>> 0), 2**53) | 0)))) < Math.fround(Math.imul((( ~ (Math.min((0.000000000000001 | 0), (y | 0)) | 0)) && x), Math.asin((1/0 >>> 0))))))))); }); testMathyFunction(mathy5, [0.000000000000001, 0x100000000, 1/0, 2**53+2, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, 0x100000001, -1/0, 1, -0x100000001, 0x080000001, -0x0ffffffff, 0, 2**53, -0x07fffffff, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-248247344*/count=310; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a2, 2, { configurable: false, enumerable: true, get: (function(j) { f0(j); }), set: f1 });");
/*fuzzSeed-248247344*/count=311; tryItOut("testMathyFunction(mathy4, /*MARR*/[new Number(1), null, new Number(1), {}, null, {}, null, {}, null, new Number(1), {}, {}, null, new Number(1), new Number(1), {}, new Number(1), new Number(1), {}, {}, null, new Number(1), {}, {}, new Number(1), {}, null, {}, new Number(1), null, {}, {}, null]); ");
/*fuzzSeed-248247344*/count=312; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (((0xffdbbfc1)));\n    i1 = (i2);\n    i2 = ((((0x191f6e01) / (((i2)+((0x67f46f03)))>>>(((-0x8000000) <= (0x4634e95d))-(i1)))) << ((~~(16777215.0)) % (-0x8000000))) >= (((i1))|0));\n    i1 = (0x5e87cfae);\n    return (((-0xb64bff)+((i1) ? (i1) : (i1))))|0;\n  }\n  return f; })(this, {ff: (eval\u0009) = z}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=313; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return ( + (Math.max(( + Math.fround(Math.cosh(y))), (( ! (Math.min((((( - Math.fround(x)) || (( + ( ! 0x100000001)) | 0)) | 0) | 0), ((( + ( + (( + y) / ( + y)))) | 0) | 0)) | 0)) >>> 0)) >> ( + Math.hypot(( + (Math.fround(Math.fround(mathy0(( + Math.fround(( + Math.fround(-Number.MAX_SAFE_INTEGER)))), ( + (Math.max(x, (y | 0)) | 0))))) % (( - Math.fround(mathy0(Math.fround(y), ( + y)))) !== ( ~ x)))), ( + Math.pow(x, (y > (x * (x && Math.min(0x100000000, x)))))))))); }); testMathyFunction(mathy1, [42, 2**53+2, 0x080000000, -0x07fffffff, 1/0, -0x0ffffffff, -0x100000000, -0x080000000, Number.MIN_VALUE, 0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, -1/0, Number.MAX_VALUE, 0x080000001, 0/0, -Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, 2**53-2, Math.PI, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), -0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, 2**53]); ");
/*fuzzSeed-248247344*/count=314; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( ~ ( + ( + ( ~ ( + ( + y))))))) ? (Math.pow((Math.asinh(0x100000001) >>> 0), Math.atan2(( ~ y), Math.fround(-Number.MAX_SAFE_INTEGER))) >>> 0) : (( ! y) <= Math.fround((Math.cosh((y | 0)) == Math.imul(( + (1.7976931348623157e308 + (y >>> 0))), y))))); }); ");
/*fuzzSeed-248247344*/count=315; tryItOut("testMathyFunction(mathy1, [(new Boolean(false)), [], (new Number(-0)), undefined, objectEmulatingUndefined(), NaN, '/0/', null, '\\0', [0], 1, 0.1, (function(){return 0;}), ({valueOf:function(){return '0';}}), 0, '0', (new Boolean(true)), ({toString:function(){return '0';}}), false, /0/, (new Number(0)), true, (new String('')), -0, '', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-248247344*/count=316; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!\\\\\\u91ed)\\\\1|(\\ude0a|\\u7e1d{0}\\\\D?^[]+)\\\\2\", \"g\"); var s = \"\\u91ed\"; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=317; tryItOut(" \"\"  in  \"\" ;function eval(eval, x) { ((a+=19)); } /*tLoop*/for (let z of /*MARR*/[ /x/ , x, true, true, x, true,  /x/ ,  /x/ ]) { v1 = Object.prototype.isPrototypeOf.call(h2, v1); }");
/*fuzzSeed-248247344*/count=318; tryItOut("/*tLoop*/for (let x of /*MARR*/[ /x/g , arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments,  /x/g , arguments,  /x/g ,  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g , arguments, objectEmulatingUndefined(), arguments, arguments, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), arguments, objectEmulatingUndefined(), arguments, objectEmulatingUndefined()]) { var a2 = []; }");
/*fuzzSeed-248247344*/count=319; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.fround((( + Math.fround(( - Math.atanh(Math.ceil(Math.fround(Math.atan2(Math.fround(x), Math.fround(y)))))))) | 0)), (( + Math.acosh((Math.max(( + -Number.MAX_SAFE_INTEGER), (( + (y >>> 0)) >>> 0)) >>> 0))) + ( + (Math.imul((( - (((x | 0) | (Math.min(Math.log(1), x) | 0)) | 0)) >>> 0), ( + (( ~ ( + Math.imul(( + 42), ( + -0x080000001)))) | 0))) >>> 0))))); }); testMathyFunction(mathy2, [-0, 2**53+2, -0x100000000, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, 0x100000000, -0x100000001, -1/0, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 1, 2**53-2, 0x080000000, Number.MIN_VALUE, -0x080000001, 42, -0x07fffffff, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 0, -0x0ffffffff, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-248247344*/count=320; tryItOut("Array.prototype.shift.apply(a2, [i1]);\nconst z = let;a2 = arguments.callee.arguments;\n");
/*fuzzSeed-248247344*/count=321; tryItOut("\"use strict\"; i1.toString = (function(j) { if (j) { g0.t1 = new Uint32Array(17); } else { try { p2.__proto__ = g1; } catch(e0) { } try { /*MXX3*/g2.DataView.prototype.byteLength = g1.DataView.prototype.byteLength; } catch(e1) { } try { e2.has(h2); } catch(e2) { } selectforgc(o2); } });");
/*fuzzSeed-248247344*/count=322; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=323; tryItOut("mathy4 = (function(x, y) { return (( ! (( + Math.atan((Math.fround(Math.min(( + (( + Math.min(y, x)) - ((Math.tan((x | 0)) | 0) >>> 0))), ( + (y | 0)))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0x080000001, -0x100000001, -0x07fffffff, 0x0ffffffff, -0x100000000, -Number.MAX_VALUE, -(2**53), 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -0, 0/0, -0x080000000, -1/0, 0.000000000000001, Number.MAX_VALUE, 1/0, 42, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, 0x080000001, 2**53-2, Number.MIN_VALUE, Math.PI, 0x080000000, 1, 2**53]); ");
/*fuzzSeed-248247344*/count=324; tryItOut("\"use strict\"; for(let c = (offThreadCompileScript.prototype) in (/*MARR*/[new Boolean(false), [1], new Boolean(false), [1], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), [1], [1], [1], new Boolean(false), [1], [1], [1], [1], [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], [1], [1], [1], new Boolean(false), new Boolean(false), [1], [1], [1], new Boolean(false), new Boolean(false), [1], [1], [1], [1], [1], new Boolean(false), new Boolean(false), [1], [1], new Boolean(false), [1], [1], new Boolean(false), [1], new Boolean(false), [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], [1], [1], new Boolean(false), [1], [1], [1], [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], [1], [1], [1], new Boolean(false), [1], [1], [1], [1], [1], new Boolean(false), [1], [1], [1], new Boolean(false), [1], [1], [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], [1], [1], new Boolean(false)].sort(mathy4,  /x/g ))) {print(x); }");
/*fuzzSeed-248247344*/count=325; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=326; tryItOut("i2 = new Iterator(h1);");
/*fuzzSeed-248247344*/count=327; tryItOut("g1.h2.fix = (function(j) { if (j) { try { t1 = new Int16Array(g1.b2); } catch(e0) { } /*ODP-3*/Object.defineProperty(f0, \"wrappedJSObject\", { configurable: false, enumerable: (4277), writable: ( \"\"  %= window), value: e1 }); } else { try { /*MXX1*/o1 = o0.g0.Date.prototype.setUTCMinutes; } catch(e0) { } print(b1); } });");
/*fuzzSeed-248247344*/count=328; tryItOut("\"use strict\"; (true);");
/*fuzzSeed-248247344*/count=329; tryItOut("{ void 0; verifyprebarriers(); }");
/*fuzzSeed-248247344*/count=330; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=331; tryItOut("/*MXX1*/o2 = g1.EvalError.name;\nlet (kizkln, lzgonx) { a2 = Array.prototype.map.call(a2, (function mcc_() { var npjiel = 0; return function() { ++npjiel; if (/*ICCD*/npjiel % 9 == 3) { dumpln('hit!'); for (var p in e1) { try { m0.set(h2, g2); } catch(e0) { } try { v0 = evaluate(\" /x/g \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 3 != 1), noScriptRval: (x % 13 == 4), sourceIsLazy: (x % 3 == 0), catchTermination: false })); } catch(e1) { } o2.m0.has(o1.o1); } } else { dumpln('miss!'); try { m2.delete(e0); } catch(e0) { } try { v2 = r2.test; } catch(e1) { } a0.push(o1); } };})(), v1, h2); }\n");
/*fuzzSeed-248247344*/count=332; tryItOut("mathy4 = (function(x, y) { return ((Math.fround(Math.fround(( - Math.fround(mathy3((x != ( + x)), y))))) + ((((x | 0) % Math.fround(Math.expm1((x | 0)))) >>> 0) | 0)) && (Math.round(Math.pow(( + Math.round(( + y))), ( + ( ! ( + Math.log1p(y)))))) >>> 0)); }); testMathyFunction(mathy4, [-0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, -0x100000001, -0x080000001, -Number.MAX_VALUE, -1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1, 0x080000000, 0/0, -(2**53), 0x100000000, -0, 42, 0x080000001, 2**53, Number.MIN_SAFE_INTEGER, Math.PI, 0, Number.MIN_VALUE, 2**53-2, 2**53+2, -0x100000000, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=333; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=334; tryItOut("/*oLoop*/for (let otzqco = 0; otzqco < 24; ++otzqco) { function shapeyConstructor(yrglob){this[\"isSealed\"] = new RegExp(\"[^](?:\\\\b{1})*\", \"yi\");if (6) { print(-12); } if (yrglob) this[\"getUint16\"] = -8;if ( /x/g ) for (var ytqrzjcva in this) { }Object.preventExtensions(this);this[\"isSealed\"] = \"\\u8A15\";this[\"getUint16\"] =  /x/ ;this[\"isSealed\"] = -22;return this; }/*tLoopC*/for (let a of /*PTHR*/(function() { for (var i of []) { yield i; } })()) { try{let wpgfgo = shapeyConstructor(a); print('EETT'); print(wpgfgo);}catch(e){print('TTEE ' + e); } } } ");
/*fuzzSeed-248247344*/count=335; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = ((/*FFI*/ff(((d0)), ((d0)), ((+(1.0/0.0))), ((0x40e23ab)), ((((0xbab33520)) ^ ((0xb39d2d33)))))|0) ? (0x93aa68fc) : (!(0x469ba3)));\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: -23}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=336; tryItOut("let(e = (ArrayBuffer()), x, x =  /* Comment */16, b = e, fwmzwp, jjcfwh, y, z) { /\\S|(?!(?=^)*\\W)/gim}return;");
/*fuzzSeed-248247344*/count=337; tryItOut("\"use strict\"; this.o2.a2.shift(h0, s0, a2, i2);");
/*fuzzSeed-248247344*/count=338; tryItOut("mathy1 = (function(x, y) { return (Math.fround(( ~ Math.fround(( - ( + Math.fround(Math.min(Math.fround(( + ( - ( + ( + mathy0(( + ( ~ (-0x080000001 >>> 0))), ( + x))))))), ( + mathy0(1, (((y >>> 0) ? (0x100000001 >>> 0) : (y >>> 0)) >>> 0)))))))))) ? Math.abs(Math.sign(((( + (0x0ffffffff ? x : (1 | 0))) === (Math.fround(x) && Math.fround(0x100000001))) != (Math.sin(y) >>> 0)))) : Math.hypot(Math.fround(Math.expm1(Math.fround(((((x >>> 0) >> (Math.sign(y) >>> 0)) >>> 0) ? y : x)))), (Math.atan2((y | 0), ( + Math.fround(mathy0(Math.fround(x), ( + Math.ceil(x)))))) | 0))); }); ");
/*fuzzSeed-248247344*/count=339; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return Math.hypot(( + Math.cbrt(mathy2(y, ( + ( + Math.expm1(Math.fround(x))))))), (( - ( + ( + ( - ( + mathy3(( + Math.cosh(y)), ( + mathy2((x % y), y)))))))) || Math.hypot(Math.atan2(( + Math.cos(Math.min(Math.fround(Math.fround((-Number.MAX_VALUE ? y : x))), Math.expm1(-0)))), 0x0ffffffff), (y | 0)))); }); testMathyFunction(mathy4, [1, -Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 0, -Number.MAX_VALUE, -0x080000001, 0x080000000, 0x100000001, -(2**53+2), -0x100000001, -0, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, -(2**53-2), 1/0, 0x0ffffffff, -0x07fffffff, 0x07fffffff, 2**53, -1/0, 2**53-2, 0x080000001, 1.7976931348623157e308, -(2**53), 2**53+2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-248247344*/count=340; tryItOut("\"use strict\"; v0 = r0.unicode;\nt1[({valueOf: function() { v1 = Object.prototype.isPrototypeOf.call(f2, a2);return 19; }})];\n");
/*fuzzSeed-248247344*/count=341; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-248247344*/count=342; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53, -0x0ffffffff, -(2**53), 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0, 0x080000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, 2**53-2, Math.PI, 0x07fffffff, Number.MIN_VALUE, 0/0, -0, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), -0x100000001, 1, -0x080000001, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=343; tryItOut("o1.o2.v1 = (p2 instanceof i1);");
/*fuzzSeed-248247344*/count=344; tryItOut("/*RXUB*/var r = r0; var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=345; tryItOut("v1.__iterator__ = (function() { try { Array.prototype.unshift.apply(a1, []); } catch(e0) { } try { for (var p in e0) { try { for (var p in h1) { try { s0 = Array.prototype.join.apply(a0, [s0]); } catch(e0) { } (Math.atan2(0, ({__parent__: (Math.atan2(24,  /x/g )) }))); } } catch(e0) { } try { m1 + a0; } catch(e1) { } g1.e1 = new Set(e0); } } catch(e1) { } s1.valueOf = (function mcc_() { var tvmmzg = 0; return function() { ++tvmmzg; o2.f0(true);};})(); return v2; });");
/*fuzzSeed-248247344*/count=346; tryItOut("/*tLoop*/for (let x of /*MARR*/[x, null, x, null, x, x, {}, null, x, null, null, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined()]) { if(new RegExp(\"(?=^?)\\\\2?\", \"yi\")) { if (x) {print(null);t1[2] = s1; }} else [1]; }");
/*fuzzSeed-248247344*/count=347; tryItOut("mathy0 = (function(x, y) { return ((( - ((y ? ((function(id) { return id } >= (x && (x << (( - (x >>> 0)) >>> 0)))) | 0) : ( - x)) >>> 0)) >>> 0) % Math.round((Math.pow(x, Math.fround(( ! x))) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[new String('q'), x, x, x, x, x, x, x, x, new Boolean(true), x, new Boolean(true), x, new Boolean(true), new Boolean(true), x, x, x, new Boolean(true), new Boolean(true), x, x, new String('q'), new Boolean(true), x, x, x, x, x, x, new String('q'), new Boolean(true), new String('q'), x, new String('q'), x, x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new Boolean(true), new String('q'), new String('q'), new String('q'), new Boolean(true), new String('q'), x]); ");
/*fuzzSeed-248247344*/count=348; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.pow((Math.ceil((Math.acosh((Math.asin((( + (( + ( + (Math.PI * Math.fround(x)))) | ( + 0x07fffffff))) | 0)) >>> 0)) >>> 0)) | 0), ((Math.expm1((mathy0(x, Math.fround(Math.acosh(y))) >>> 0)) >>> 0) | 0)) | 0)); }); ");
/*fuzzSeed-248247344*/count=349; tryItOut("\"use strict\"; v2 = evaluate(\"let v1 = Array.prototype.reduce, reduceRight.apply(a1, [(function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) { var r0 = a4 % x; var r1 = a2 & 8; var r2 = a5 | 9; a0 = 4 + a1; var r3 = a2 + a1; var r4 = a3 & a1; var r5 = 4 ^ a3; var r6 = 1 - a0; var r7 = r0 / 2; var r8 = 3 * r5; var r9 = r4 + 0; var r10 = r4 / 0; print(a0); var r11 = a9 | 6; x = r9 % 4; var r12 = 9 - r4; var r13 = r12 ^ a7; var r14 = r8 | 0; print(a9); var r15 = 0 - 9; r6 = 1 | a4; var r16 = r9 - r8; var r17 = a1 - a8; var r18 = 2 | r13; r8 = r4 + 9; var r19 = 8 | 0; var r20 = a8 / r8; var r21 = a3 / r12; var r22 = r9 & r2; var r23 = a2 / r15; r2 = r5 + a4; var r24 = 2 | a2; var r25 = r22 * r23; var r26 = 1 / r6; var r27 = r4 * r26; var r28 = r24 / a9; var r29 = 4 - r16; var r30 = r24 ^ 1; var r31 = 3 - 6; var r32 = r1 % 2; var r33 = 3 + r10; var r34 = r27 * r32; var r35 = 2 - r12; var r36 = 5 / 8; r7 = r9 ^ r27; var r37 = a4 % a10; var r38 = r23 / r14; var r39 = 6 + r28; a6 = a1 % r20; var r40 = r4 * a9; var r41 = a0 ^ 3; var r42 = 5 | 7; var r43 = 7 | a3; var r44 = r35 + r18; var r45 = 4 - r14; var r46 = a5 / 4; var r47 = r27 ^ r45; print(r13); var r48 = 4 & r28; var r49 = 5 ^ r27; var r50 = r48 % r31; var r51 = a6 & r38; var r52 = r18 % r4; print(x); r38 = r42 ^ r4; var r53 = 5 / 2; var r54 = 6 - r35; var r55 = r43 / r28; var r56 = a10 ^ r44; var r57 = r10 / 4; var r58 = r37 | r29; var r59 = 8 - 3; var r60 = r58 | r57; var r61 = 0 ^ 2; r37 = r21 + r25; r16 = 3 | a0; var r62 = r3 ^ 3; var r63 = r49 & r35; var r64 = r34 - r60; var r65 = x & r50; r45 = a1 | a7; var r66 = a5 % 4; var r67 = r61 % 8; var r68 = r57 - 8; var r69 = r42 ^ r60; var r70 = r7 + r0; var r71 = r34 / r17; var r72 = 6 ^ 5; var r73 = 4 * r49; var r74 = r0 - x; var r75 = 0 / r47; var r76 = 6 ^ x; print(r72); print(r64); var r77 = r29 & 2; var r78 = r25 + 4; var r79 = r17 | r51; var r80 = a10 & r57; var r81 = 9 * r22; var r82 = 0 / r18; var r83 = r71 / r36; r22 = r32 * r32; r57 = a2 - r35; var r84 = 5 % r51; r24 = 5 - r42; var r85 = 9 | r69; var r86 = r40 & 4; var r87 = r29 / r36; print(r38); var r88 = 4 ^ r26; var r89 = 0 - 8; var r90 = 4 / r31; var r91 = r4 | r35; var r92 = r47 / 0; var r93 = r64 - 0; var r94 = r23 & 9; var r95 = 8 ^ r80; var r96 = 9 + a2; var r97 = r31 ^ r81; var r98 = r28 - r39; var r99 = 4 - 9; var r100 = 9 / 5; print(r23); r35 = r79 ^ 0; a4 = r37 / 9; var r101 = a2 & 2; var r102 = 4 % r79; var r103 = 0 % r5; var r104 = r72 & r72; var r105 = r2 * r6; var r106 = 1 ^ r88; var r107 = a0 | 7; var r108 = 2 ^ 2; var r109 = r57 & 0; var r110 = r34 & r31; var r111 = r56 | r52; var r112 = r105 - r100; var r113 = r49 | r15; var r114 = 8 * a2; var r115 = r94 % r59; var r116 = 6 + r79; var r117 = r59 - 3; r110 = 4 ^ r22; var r118 = 3 + r11; print(r87); r65 = r49 & r96; r4 = 1 - 5; r46 = r87 - r54; a4 = r27 % r52; var r119 = r63 & r102; print(r104); var r120 = r28 - r50; var r121 = 6 / r101; var r122 = r67 | r68; var r123 = 7 - 1; var r124 = 3 / 0; var r125 = 3 | r2; var r126 = r31 - 5; var r127 = r99 ^ r85; var r128 = r28 | a4; var r129 = r49 + r103; var r130 = r122 / 4; var r131 = r60 + r82; r20 = r31 + r93; var r132 = a8 + r23; var r133 = r27 ^ r3; r71 = a10 / 6; r98 = r76 - r66; var r134 = r118 / r90; var r135 = r87 - r48; var r136 = r88 ^ r82; var r137 = r77 ^ 5; var r138 = 5 - r42; r18 = r30 / r97; var r139 = 9 * 5; var r140 = r106 / r53; a2 = r95 / 6; var r141 = r82 - r21; var r142 = r119 * 5; var r143 = r30 % r43; r134 = 8 ^ r3; var r144 = 0 ^ r139; var r145 = 8 & 5; var r146 = r67 ^ 6; var r147 = r12 & r73; var r148 = 9 + 1; var r149 = r109 / r112; var r150 = a7 * 0; var r151 = r115 | 1; var r152 = r17 / 0; var r153 = 7 + r140; var r154 = 0 % r102; r10 = r50 & 6; var r155 = r50 & r74; var r156 = r21 - r110; var r157 = 4 / 0; var r158 = 3 | r152; r141 = r12 & r112; var r159 = r117 | r77; var r160 = r120 + r91; print(r117); var r161 = r79 | r2; r60 = r21 + r68; var r162 = 0 | 9; var r163 = r47 | 0; var r164 = a3 ^ 9; var r165 = r97 | r58; var r166 = 4 ^ 4; var r167 = r129 + r30; var r168 = a9 & 0; var r169 = r6 / r80; r136 = a6 * r35; var r170 = r46 | r111; r3 = r16 & r100; var r171 = a4 / r52; var r172 = r34 / r162; r79 = 7 - r164; var r173 = 8 ^ 5; var r174 = 6 ^ r42; var r175 = r8 | r20; var r176 = 6 * 0; var r177 = a1 + r45; var r178 = r9 | 4; var r179 = r105 ^ r87; var r180 = r53 - 6; var r181 = r141 & r56; var r182 = r48 - r47; r136 = r36 % 6; var r183 = r72 | r134; var r184 = r44 | a1; r178 = r18 | 5; var r185 = 0 ^ r160; var r186 = r21 / r133; var r187 = r79 - r134; print(r158); r124 = 5 / a2; var r188 = 2 * r48; var r189 = r127 & r89; var r190 = r84 & r181; var r191 = r138 * r79; print(r98); var r192 = r103 - 1; var r193 = 7 % 3; r102 = r62 / r163; var r194 = r190 * r151; var r195 = r129 * r8; r92 = a7 * 4; var r196 = 8 / 1; var r197 = r165 + r8; var r198 = 9 * 9; var r199 = 6 + 4; var r200 = 4 & r18; var r201 = r165 ^ r117; var r202 = r146 ^ r88; a7 = 0 % a10; var r203 = r126 % 0; var r204 = r138 & r156; var r205 = r35 - r102; r8 = 4 & 2; r178 = r52 + r2; var r206 = 0 ^ 9; var r207 = r202 ^ 5; var r208 = 5 - 6; a4 = r192 & a5; var r209 = 2 % r190; var r210 = r39 + r30; var r211 = 3 & 4; var r212 = r154 | 9; r113 = r179 & r76; var r213 = 4 / r20; var r214 = 9 | 2; var r215 = r104 ^ a6; print(r162); r133 = r194 ^ r166; r7 = 8 + r42; var r216 = r137 + a2; var r217 = r34 ^ 7; r55 = r72 % r4; var r218 = r128 ^ r192; var r219 = r143 + r161; var r220 = r200 & r209; r179 = 6 % 3; print(r43); var r221 = 4 * r124; r95 = r56 | r212; r61 = 8 & r111; r71 = r77 & 9; var r222 = r117 & r57; var r223 = r92 / r207; var r224 = r152 / 7; var r225 = r132 * r51; var r226 = r63 + r81; var r227 = r154 ^ 6; var r228 = r216 % r77; print(r100); var r229 = 7 - r91; var r230 = 7 + r115; var r231 = 7 - a5; var r232 = r158 ^ r38; var r233 = r113 / r33; var r234 = r1 + r109; var r235 = r103 ^ r28; var r236 = r118 % r161; var r237 = 8 ^ 6; var r238 = r216 | r16; var r239 = r10 ^ 5; var r240 = a5 - r186; var r241 = a0 | r139; var r242 = r178 | r208; var r243 = r238 * r190; r79 = 2 & 6; var r244 = r42 - 8; var r245 = r62 & r239; var r246 = 9 % r131; var r247 = 0 + a3; var r248 = r100 | r0; var r249 = r42 / 1; print(r163); var r250 = 1 * r249; var r251 = 3 + 1; var r252 = 4 % 9; var r253 = r183 / 8; var r254 = 7 & 0; var r255 = r104 ^ r87; var r256 = 1 ^ 6; r146 = 3 ^ 8; var r257 = 0 / r251; var r258 = r256 - r131; r133 = r112 % r86; var r259 = r203 + r230; var r260 = r234 + r244; var r261 = 1 ^ r245; var r262 = r125 | r29; var r263 = 9 ^ 3; var r264 = r166 | r48; var r265 = 8 & r264; var r266 = r199 % r169; r168 = r115 % r94; var r267 = r9 ^ a9; var r268 = r57 - a2; var r269 = 5 * 4; var r270 = 7 / 9; var r271 = r240 * 8; var r272 = 8 / r211; r251 = r102 ^ a9; var r273 = r261 | 4; var r274 = r273 / 7; var r275 = 3 ^ a2; var r276 = 8 - 1; var r277 = r73 & r223; var r278 = 7 + r170; var r279 = 0 / r141; r131 = x - 5; r174 = r239 / r265; r227 = r154 % 0; var r280 = r55 ^ 6; var r281 = r217 & 5; r160 = 1 % r124; var r282 = r208 / 1; var r283 = 4 ^ 6; r70 = r49 % r166; a0 = r18 ^ r32; r157 = 9 % r110; var r284 = 3 | r187; var r285 = 4 & 0; var r286 = 5 & r234; r128 = r175 / r20; var r287 = 7 - r243; r142 = r11 - r67; var r288 = 4 ^ r206; var r289 = r178 - r202; var r290 = r107 + r190; var r291 = 1 ^ r28; var r292 = r111 % r24; var r293 = r16 + r243; var r294 = r228 & r265; var r295 = r213 % r47; var r296 = 9 ^ r203; var r297 = r89 - r215; var r298 = 9 - r16; var r299 = r247 * r91; var r300 = 0 * 4; var r301 = 4 + r109; var r302 = 8 + r49; var r303 = r270 / 9; var r304 = r264 | r161; var r305 = r133 - 5; var r306 = r178 - r232; r246 = r16 / r206; var r307 = r82 | r300; var r308 = 5 / 0; var r309 = r12 / r262; var r310 = r104 / 9; var r311 = r187 / r48; var r312 = 0 - r273; var r313 = r163 - r291; var r314 = r174 ^ r41; var r315 = r301 / 0; var r316 = 1 % 6; var r317 = 3 + r124; r282 = r13 - 6; r114 = 0 + r38; r244 = r33 - r18; r46 = r146 % 6; r168 = r225 - 1; r235 = r268 % r204; var r318 = 1 ^ 8; var r319 = r164 | 6; r22 = 6 & r319; var r320 = r107 % r85; r152 = r136 + r134; r187 = r257 | 7; var r321 = r110 * r282; var r322 = r78 & r232; var r323 = r122 & r35; print(r137); r89 = r176 & 6; var r324 = 5 - r71; var r325 = r272 % 0; var r326 = r281 * r130; r228 = r11 % r5; var r327 = r321 ^ r13; var r328 = r234 + 2; var r329 = 1 ^ r220; var r330 = 6 & r134; var r331 = r180 % r295; var r332 = r212 - r189; var r333 = r133 ^ 6; var r334 = r266 / r87; var r335 = 1 * r298; a3 = r79 * r102; var r336 = 9 ^ r177; var r337 = r290 | 2; var r338 = r259 / 0; r70 = a8 % r198; r36 = r8 & r304; r140 = 3 + 6; var r339 = r55 * 4; var r340 = r263 | r289; var r341 = r167 ^ r190; var r342 = 7 & r87; var r343 = r137 * a3; var r344 = r137 % r269; r17 = 4 ^ a9; var r345 = r127 ^ r107; r311 = a3 - r323; var r346 = r208 ^ 6; var r347 = r113 * 5; print(r252); var r348 = r178 ^ r173; var r349 = r128 ^ r345; var r350 = 3 ^ 6; var r351 = r255 - r153; var r352 = r82 / 5; var r353 = r118 & r24; print(r103); var r354 = r317 ^ r87; var r355 = r47 | 8; r265 = r334 | r117; var r356 = r26 | 0; r316 = r59 * 8; var r357 = r51 + r324; var r358 = r210 & r35; var r359 = r129 - r130; var r360 = 3 & r203; var r361 = r139 + 0; var r362 = r201 - r293; return a8; }), v2, e1, o2]);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: \nx, noScriptRval: (x % 2 == 0), sourceIsLazy: x, catchTermination: false, elementAttributeName: s2, sourceMapURL: s1 }));");
/*fuzzSeed-248247344*/count=350; tryItOut("v2 = (o2 instanceof t2);");
/*fuzzSeed-248247344*/count=351; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! ((Math.sign(x) >>> 0) | 0)) != Math.log2(Math.hypot(Math.max(mathy3(x, Math.atanh(y)), x), -0x080000000))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -0, -(2**53), -Number.MIN_VALUE, 0, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 0x080000001, 1.7976931348623157e308, -1/0, 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), Math.PI, 2**53+2, 2**53, -0x080000000, 42, 0x0ffffffff, 0.000000000000001, 0x07fffffff, 1/0, Number.MIN_VALUE, 0x100000001, -0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 1, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=352; tryItOut("\"use strict\"; p2 + s0;");
/*fuzzSeed-248247344*/count=353; tryItOut("testMathyFunction(mathy2, [0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, 2**53-2, 0x07fffffff, -0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000000, -(2**53), 42, 0x100000001, 0.000000000000001, 2**53, 2**53+2, -(2**53+2), 0x0ffffffff, -0x0ffffffff, -(2**53-2), 0x100000000, 0, -0x080000001, -1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 1, Math.PI]); ");
/*fuzzSeed-248247344*/count=354; tryItOut("var nonesy = new SharedArrayBuffer(0); var nonesy_0 = new Float64Array(nonesy); nonesy_0[0] = -15; var nonesy_1 = new Int32Array(nonesy); nonesy_1[0] = 21; var nonesy_2 = new Uint8ClampedArray(nonesy); nonesy_2[0] = -19; var nonesy_3 = new Int8Array(nonesy); print(nonesy_3[0]); v2 = Array.prototype.every.call(a1, (function(j) { if (j) { t2 = t0.subarray(16); } else { try { v1 = t0.length; } catch(e0) { } try { a2.splice(NaN, this.v0, this.g0); } catch(e1) { } try { o1.valueOf = (function(j) { if (j) { try { h2.has = (function() { try { ; } catch(e0) { } try { this.v0 = g2.eval(\"o1.v0 = a1.length;\"); } catch(e1) { } h1 + ''; return a1; }); } catch(e0) { } Array.prototype.unshift.apply(a2, [ '' , i2, h0]); } else { try { a0[13] = g1; } catch(e0) { } try { Array.prototype.splice.apply(a0, [6, 13]); } catch(e1) { } try { h1.getOwnPropertyDescriptor = (function mcc_() { var xzduqp = 0; return function() { ++xzduqp; if (/*ICCD*/xzduqp % 9 == 0) { dumpln('hit!'); try { this.e1.delete(a0); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(f1, g0.i0); } else { dumpln('miss!'); Array.prototype.sort.call(a0, (function() { try { t1[2]; } catch(e0) { } /*ADP-1*/Object.defineProperty(a1, ({valueOf: function() { v0 = Object.prototype.isPrototypeOf.call(f1, t2);return 9; }}), ({get: mathy4})); return s0; }), e0); } };})(); } catch(e2) { } s1 += s0; } }); } catch(e2) { } m2 = new Map; } }), s1);h2.toString = (function() { for (var j=0;j<8;++j) { f0(j%4==0); } });a1.shift();undefined;v0 = Object.prototype.isPrototypeOf.call(h2, g0);{}Array.prototype.forEach.call(a0, (function(j) { if (j) { try { h2 = a0[2]; } catch(e0) { } try { g1.t0.set(t0, 19); } catch(e1) { } try { g0.v2 = evalcx(\" '' \", g1); } catch(e2) { } v0 = t1.length; } else { try { this.h0.getOwnPropertyDescriptor = f0; } catch(e0) { } try { v2 = this.t2.length; } catch(e1) { } m2.has( /x/g ); } }));");
/*fuzzSeed-248247344*/count=355; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var asin = stdlib.Math.asin;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+(0.0/0.0));\n    d0 = (d1);\n    d1 = (+(0.0/0.0));\n    d1 = (+ceil(((d1))));\n    return +((+asin(((d1)))));\n  }\n  return f; })(this, {ff: Array.prototype.every}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1, objectEmulatingUndefined(), (new Boolean(false)), (new Boolean(true)), (new Number(-0)), ({valueOf:function(){return 0;}}), '/0/', '\\0', '0', NaN, 0, [0], (new String('')), null, (function(){return 0;}), false, 0.1, ({toString:function(){return '0';}}), '', ({valueOf:function(){return '0';}}), (new Number(0)), true, undefined, /0/, [], -0]); ");
/*fuzzSeed-248247344*/count=356; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[new String(''), new String(''), new String(''), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), Infinity, Infinity, objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), Infinity, new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), Infinity, objectEmulatingUndefined()]) { o2.v0 = evaluate(\"mathy0 = (function(x, y) { \\\"use strict\\\"; return ( + (( + ( + Math.pow(Math.fround(( ~ 2**53+2)), Math.fround(Math.atan2(( - (y | 0)), (Math.atan((-(2**53) | 0)) | 0)))))) >> ( + Math.fround(Math.hypot(Math.fround(y), Math.fround((y != x))))))); }); testMathyFunction(mathy0, [0x080000000, 0, -0, -0x100000000, -0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -(2**53), 0/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, -(2**53+2), 1, 1/0, -1/0, 2**53, -0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, 42, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000001]); \", ({ global: g0.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: false, elementAttributeName: s1 })); }");
/*fuzzSeed-248247344*/count=357; tryItOut("const b, x = ([c]), y, z = y, w, \u3056, \u3056, lfmicu, dbsehv, d;/*RXUB*/var r = /(\\d)+/; var s = \"0\"; print(r.exec(s)); ");
/*fuzzSeed-248247344*/count=358; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), new Number(1),  '' ,  '' , objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , objectEmulatingUndefined(),  '' ,  '' , objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(),  '' , new Number(1)]) { g1.s2 = new String; }");
/*fuzzSeed-248247344*/count=359; tryItOut("a0.unshift(((({ get prototype x (x, w)Math.exp(28),  set -20 x (eval, x, \u3056, x, x, d, \u3056, eval, w, x, e, x, \u3056, y, x, d, eval = new RegExp(\"())+|(?:(?![^])|(?=\\\\B{1,5}){3})\", \"m\"), x, b, y, x, x, z, c, x, d, c, x, x = \"\\u2F39\", x, b, c = window, w, window = a, of, this, x, x, eval, x = window, w, this.b, a, e, b, w, x = x, let, y, x, x, z, x, x, w = this, x = new RegExp(\"(?!.)\", \"g\"), \u3056, x = 24, x, x, \u3056, x, x, x, e = -28, \u3056, x, x, x, x = ({a1:1}),  ) { yield x }  })).valueOf(\"number\")), t0);");
/*fuzzSeed-248247344*/count=360; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[0x20000000, 3/0, NaN, 0x20000000]) { f1 + f1; }");
/*fuzzSeed-248247344*/count=361; tryItOut("mathy4 = (function(x, y) { return ((( + (x != ( + mathy3(( + 0/0), Math.fround(y))))) ? ( ! (( + (y >>> 0)) | 0)) : Math.imul(0, ( + (x >>> 0)))) ^ (( + Math.imul(Math.fround((Math.fround(x) - Math.fround(x))), ( + ((Math.fround(y) ^ Math.fround(0x0ffffffff)) | 0)))) - (0x100000000 ? Math.atan2(y, ( + 0x100000000)) : (( + (( + 0x080000001) ? ( + x) : ( + (Math.exp(Math.fround(y)) | 0)))) , x)))); }); testMathyFunction(mathy4, /*MARR*/[(0/0), (0/0), null, (0/0), null, new Number(1.5), new Number(1.5), null, (0/0), -(2**53+2), -(2**53+2), null, -(2**53+2), (0/0), (0/0), (0/0), -(2**53+2), null, null, null, new Number(1.5), new Number(1.5), -(2**53+2), -(2**53+2), null, null, null, null, null, null, -(2**53+2), null, -(2**53+2), null, null, new Number(1.5), new Number(1.5), null, -(2**53+2), (0/0), -(2**53+2), new Number(1.5), null, new Number(1.5), -(2**53+2), -(2**53+2), -(2**53+2), (0/0), new Number(1.5), null, new Number(1.5), (0/0), (0/0), -(2**53+2), new Number(1.5), null, -(2**53+2), (0/0), (0/0), -(2**53+2), new Number(1.5), null, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=362; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.log1p((mathy4(((( + (Math.pow(x, x) >>> 0)) % x) >>> 0), (mathy0(( - (x >>> 0)), y) >>> 0)) | ((((Math.pow(y, 0.000000000000001) ? -Number.MAX_SAFE_INTEGER : x) >>> 0) - mathy1((y >>> 0), ( + Math.max(( + y), ( + -0x07fffffff))))) & ( - Math.fround(Math.hypot(Math.pow(-Number.MIN_SAFE_INTEGER, y), x)))))); }); testMathyFunction(mathy5, [-0x0ffffffff, 2**53+2, -0x100000000, 0/0, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 0, Number.MAX_SAFE_INTEGER, 42, 1, -0x100000001, 0.000000000000001, -(2**53+2), -0, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), -(2**53-2), 0x100000000, 0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 0x100000001, -1/0, -0x07fffffff, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-248247344*/count=363; tryItOut("a1.pop();");
/*fuzzSeed-248247344*/count=364; tryItOut("/*MXX1*/o1 = g1.g1.Promise.race;");
/*fuzzSeed-248247344*/count=365; tryItOut("testMathyFunction(mathy1, [-0x07fffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 1, 1/0, -0x100000001, Number.MIN_VALUE, 2**53+2, 0.000000000000001, -(2**53-2), 0x100000000, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0, 0, -(2**53), -0x080000001, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, Math.PI, 0x080000000, 2**53, 0x0ffffffff, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2]); ");
/*fuzzSeed-248247344*/count=366; tryItOut("h0.toString = Object.isSealed;");
/*fuzzSeed-248247344*/count=367; tryItOut("t0[({valueOf: function() { { void 0; gcslice(243); }return 6; }})] = (4277);");
/*fuzzSeed-248247344*/count=368; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=369; tryItOut("\"use strict\"; o1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 295147905179352830000.0;\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: mathy0}, new SharedArrayBuffer(4096));");
/*fuzzSeed-248247344*/count=370; tryItOut("\"use strict\"; Array.from");
/*fuzzSeed-248247344*/count=371; tryItOut("mathy2 = (function(x, y) { return Math.clz32((Math.pow((((( + Math.fround(mathy1(Math.fround(x), Math.fround((Math.imul(y, (y | 0)) >>> (-(2**53-2) >>> 0)))))) | 0) ? (x | 0) : (0 | 0)) | 0), (Math.clz32(( ! Math.asinh(y))) & (/*tLoop*/for (let e of /*MARR*/[ /x/ ,  /x/ ,  /x/ , [1], objectEmulatingUndefined(),  /x/ , {x:3}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {x:3}, {x:3},  /x/ , {x:3}, objectEmulatingUndefined(),  /x/ , [1], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), {x:3},  /x/ ,  /x/ , {x:3}, objectEmulatingUndefined(), objectEmulatingUndefined(), [1], {x:3}, objectEmulatingUndefined(),  /x/ , {x:3}, [1], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , {x:3}, {x:3}, [1], objectEmulatingUndefined(),  /x/ ,  /x/ , [1], [1], objectEmulatingUndefined(), {x:3}, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined()]) { print( '' ); } <= ((y ^ (y | 0)) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=372; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy2((mathy2((Math.fround(mathy2(Math.fround(Math.fround(Math.hypot(2**53-2, -0x0ffffffff))), ( + ( ~ ( + (( + Math.min(Math.fround(0x100000000), ( + y))) | ( ! (x ** Math.fround(x))))))))) | 0), Math.fround(mathy0(y, y))) >>> 0), ( + Math.log10(( + Math.atan2(( ~ 2**53+2), (x >> Math.imul((x | 0), (x | 0)))))))); }); testMathyFunction(mathy3, [-(2**53), 2**53+2, -Number.MIN_VALUE, -0x080000001, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, Math.PI, 0x080000000, 0x100000001, -(2**53+2), -0x07fffffff, 1.7976931348623157e308, 2**53-2, 0, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, -0x100000000, 1/0, -0x100000001, Number.MIN_VALUE, -0x080000000, 42, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, -0]); ");
/*fuzzSeed-248247344*/count=373; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0, -1/0, 0/0, 1, 1/0, 2**53-2, 1.7976931348623157e308, 42, -(2**53-2), 2**53, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, -(2**53), -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, Math.PI, 0x080000001, Number.MAX_VALUE, -0, 0x100000001, -0x080000001, -0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=374; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=375; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! (Math.max((( + (( + y) !== ( + Math.log(Math.fround(y))))) | 0), ( + Math.min((((x >>> 0) > (-(2**53) >>> 0)) >>> 0), mathy0(y, Math.hypot(((0x100000000 && (y >>> 0)) >>> 0), x))))) !== ((Math.max((Math.sign((x >>> 0)) >>> 0), Math.log(((x > 0x0ffffffff) < x))) && ((((((( ! y) | y) | 0) != (y | 0)) >>> 0) >> -Number.MIN_VALUE) | 0)) | 0))); }); ");
/*fuzzSeed-248247344*/count=376; tryItOut("t2[10] = (void shapeOf(yield \"\\u5CAD\" || ({ get e()\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (i2);\n    }\n    i1 = ((0x6b2745c7) <= (-0x8000000));\n    return ((new Float32Array()))|0;\n  }\n  return f; }) <<= Promise));");
/*fuzzSeed-248247344*/count=377; tryItOut("L:for([c, z] = (p={}, (p.z = (x >> b))()) in (/*MARR*/[null, NaN, NaN, null, null, NaN, NaN, null, NaN, null, null, NaN, NaN, null, null, NaN, null, null, NaN, NaN, NaN, null, NaN, NaN, NaN, null, null, null, NaN, NaN, NaN, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, NaN, null, null].filter)) with(a.d)break ;");
/*fuzzSeed-248247344*/count=378; tryItOut("Array.prototype.reverse.apply(a2, []);");
/*fuzzSeed-248247344*/count=379; tryItOut("mathy5 = (function(x, y) { return (( + ((Math.clz32(Math.fround(((Math.round(Math.fround(x)) >>> 0) % Math.fround(( + Math.fround(y)))))) >>> 0) / Math.atan2(y, ((Math.fround((Math.fround(y) != Math.fround(-Number.MAX_VALUE))) ** x) >>> 0)))) >>> Math.atan2((Math.log10(Math.fround(y)) >>> 0), ((Math.exp((Math.exp(Math.atan2(x, Math.fround((( + (y >>> 0)) >>> 0)))) | 0)) >>> 0) >> ( ~ (y >>> 0))))); }); testMathyFunction(mathy5, /*MARR*/[delete x = ((makeFinalizeObserver('tenured'))),  '\\0' ,  '\\0' , false,  '\\0' , delete x = ((makeFinalizeObserver('tenured'))), true, delete x = ((makeFinalizeObserver('tenured'))), true, false, true, true]); ");
/*fuzzSeed-248247344*/count=380; tryItOut("m1.get((4277));");
/*fuzzSeed-248247344*/count=381; tryItOut("\"use strict\"; m2 = new WeakMap;let d = (e =  \"\" );");
/*fuzzSeed-248247344*/count=382; tryItOut("testMathyFunction(mathy3, [0x07fffffff, 0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, -0x080000000, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, 0/0, -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, -0x080000001, -0x100000000, 2**53, -0x100000001, 42, -1/0, -0, Number.MIN_VALUE, -(2**53), Math.PI, -0x07fffffff, -(2**53+2), 2**53-2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-248247344*/count=383; tryItOut("/*infloop*/for(var (x) in (((/*wrap3*/(function(){ \"use asm\"; var hywslb = [,,]; ((let (e=eval) e))(); })).bind)(x)))print(x);");
/*fuzzSeed-248247344*/count=384; tryItOut("\"use strict\"; m0.has(i0);");
/*fuzzSeed-248247344*/count=385; tryItOut("testMathyFunction(mathy3, [-0x0ffffffff, -1/0, 0x080000000, -(2**53), -Number.MIN_VALUE, -(2**53+2), 0/0, 0x07fffffff, 42, 0x100000000, 2**53, 1, -0x080000001, Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, 0.000000000000001, 1/0, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53-2), Math.PI, 0x080000001, -0x080000000, 0, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, -0]); ");
/*fuzzSeed-248247344*/count=386; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( - (Math.cosh(Math.round(y)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0, 42, -0x100000001, 0.000000000000001, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, 2**53-2, 0, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 1, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0x080000000, -0x100000000, -0x07fffffff, Math.PI, Number.MIN_VALUE, -1/0, 0/0, 0x07fffffff, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -0x080000000, Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-248247344*/count=387; tryItOut("p0.valueOf = (function() { try { b1 = t1.buffer; } catch(e0) { } try { /*MXX3*/this.g2.DataView.prototype.setInt8 = g0.DataView.prototype.setInt8; } catch(e1) { } for (var p in o1.a1) { try { o1 = this.t2[(void options('strict_mode'))]; } catch(e0) { } v0 = null; } return m0; });");
/*fuzzSeed-248247344*/count=388; tryItOut("print(x);");
/*fuzzSeed-248247344*/count=389; tryItOut("/*infloop*/ for  each(let x in \"\\u2A78\") {a2.reverse(Math); }");
/*fuzzSeed-248247344*/count=390; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2(((((( - ((Math.clz32((( + Math.acos(( + y))) | 0)) | 0) | 0)) | 0) | 0) / (( - ( - y)) | 0)) | 0), ( + ( + Math.fround(Math.log1p(Math.pow((((y >>> 0) ? (x >>> 0) : (y >>> 0)) >>> 0), Math.fround(( - (( + ( + y)) >> y))))))))); }); ");
/*fuzzSeed-248247344*/count=391; tryItOut("testMathyFunction(mathy5, ['0', (new Number(-0)), objectEmulatingUndefined(), NaN, 0.1, undefined, (new Boolean(true)), [0], '/0/', null, [], ({toString:function(){return '0';}}), '', 0, (new String('')), '\\0', -0, /0/, (function(){return 0;}), (new Number(0)), 1, ({valueOf:function(){return '0';}}), false, true, ({valueOf:function(){return 0;}}), (new Boolean(false))]); ");
/*fuzzSeed-248247344*/count=392; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=393; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.tan((Math.max(( + (( + (Math.tan(0.000000000000001) + y)) | 0)), ( + ( + ((Math.abs(Math.min((Math.fround(Math.atan2(Math.fround(-(2**53-2)), ( + y))) << Number.MIN_VALUE), Math.atan(42))) | 0) ? ( + ( - ( ! -Number.MIN_SAFE_INTEGER))) : x)))) >>> 0)); }); testMathyFunction(mathy0, [0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 2**53+2, 2**53, -0, 0x100000001, 0, Number.MAX_VALUE, 42, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0x07fffffff, -0x080000001, -0x100000001, -(2**53+2), -(2**53), 2**53-2, -Number.MIN_VALUE, 0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, 1, -(2**53-2), -0x080000000, 1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=394; tryItOut("\"use strict\"; v2 = evalcx(\"let (x, x, a, d, rpjuxs, ptjssd) x == this\", g2);");
/*fuzzSeed-248247344*/count=395; tryItOut("s0 = g0.o1.s0.charAt(v2);");
/*fuzzSeed-248247344*/count=396; tryItOut("t1 + t2;");
/*fuzzSeed-248247344*/count=397; tryItOut("mathy4 = (function(x, y) { return ((((Math.max((mathy2(( ~ ( + y)), (( - ((( + (Number.MIN_SAFE_INTEGER | 0)) | 0) | 0)) | 0)) >>> 0), (Math.expm1(( - 0)) >>> 0)) >>> 0) | 0) / (( + Math.round(Math.fround(Math.log1p((((mathy0(Math.fround((Math.fround(y) > Math.fround(y))), x) , y) != (Math.imul(x, x) | 0)) | 0))))) | 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, -0, -0x080000000, 0x080000001, 1, -1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, -(2**53), -(2**53+2), 0, Number.MAX_VALUE, 2**53, 0.000000000000001, 0/0, 2**53-2, 0x07fffffff, 0x100000001, -0x100000000, Number.MIN_VALUE, 1/0, Math.PI, 2**53+2, 42, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=398; tryItOut("testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, -0x07fffffff, -0x100000000, 0x100000001, 2**53, 2**53+2, 42, Number.MIN_VALUE, 0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, Number.MAX_VALUE, 0, 0x07fffffff, -Number.MAX_VALUE, -1/0, 0.000000000000001, 1.7976931348623157e308, 1, -(2**53+2), -(2**53), 0x0ffffffff, -0x100000001, 2**53-2, -0x080000000, -0x0ffffffff, 1/0, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=399; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=400; tryItOut("mathy4 = (function(x, y) { return (Math.pow((Math.fround(Math.clz32(((( ! (((Math.fround(0.000000000000001) - Math.fround(Math.fround(Math.hypot(Math.fround(y), Math.fround(x))))) >>> 0) >>> 0)) >>> 0) >= Math.fround(( - y))))) >>> 0), ( ~ Math.expm1((Math.sin(((((Math.hypot(y, x) | 0) <= x) | 0) >>> 0)) >>> 0)))) >>> 0); }); ");
/*fuzzSeed-248247344*/count=401; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + mathy1(( + (((( + (( + (x >> (x | 0))) > ( + x))) && (Math.atan2((Math.atan2(x, y) | 0), ((Math.asin(-Number.MIN_SAFE_INTEGER) ? -(2**53) : x) | 0)) | 0)) || Math.cosh(x)) | 0)), ( + mathy0(Math.fround(mathy1(( ~ Number.MIN_VALUE), Math.fround(Math.abs((( ~ x) >>> 0))))), Math.fround(Math.imul((y >>> 0), Math.fround((mathy1((0.000000000000001 >>> 0), (( + (( + y) ** (y ? (x >>> -0x080000001) : x))) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, 1.7976931348623157e308, 2**53, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -(2**53), -0x07fffffff, -0x0ffffffff, 0, -(2**53+2), 2**53-2, -1/0, -0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, -(2**53-2), -0, 0x080000001, 0.000000000000001, 42, 0x080000000, 1/0, -0x100000000, 0x100000000, 2**53+2, 1]); ");
/*fuzzSeed-248247344*/count=402; tryItOut("\"use strict\"; let (z) { print(z); }");
/*fuzzSeed-248247344*/count=403; tryItOut("\"use strict\"; v1 = evalcx(\"\\\"use asm\\\"; /*tLoop*/for (let e of /*MARR*/[ \\\"use strict\\\" ,  \\\"use strict\\\" , new Number(1.5), new Number(1.5), new Number(1.5),  \\\"use strict\\\" ,  \\\"use strict\\\" , new Number(1.5),  \\\"use strict\\\" , new Number(1.5),  \\\"use strict\\\" , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  \\\"use strict\\\" , new Number(1.5),  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" ,  \\\"use strict\\\" , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5)]) { t0 = t2.subarray(v0, 7); }\", g1);");
/*fuzzSeed-248247344*/count=404; tryItOut("v0 = this.r2.ignoreCase;");
/*fuzzSeed-248247344*/count=405; tryItOut("mathy1 = (function(x, y) { return (mathy0(Math.cbrt((( + mathy0(Math.cosh(y), ( + Math.imul(( + y), ( + 0x100000001))))) | 0)), (Math.log10((( + x) >>> 0)) >>> 0)) && (( + ( + Math.log2(( + ( ! ( + (Math.atan2((( ~ ( + ((y >>> 0) <= (-0x080000001 >>> 0)))) >>> 0), (Math.fround((Math.fround(x) <= 42)) >>> 0)) >>> 0))))))) | 0)); }); testMathyFunction(mathy1, [0, 2**53-2, 1, 2**53, 2**53+2, 0.000000000000001, -0x080000000, -0x0ffffffff, -(2**53+2), 0x100000000, Number.MAX_VALUE, 0x07fffffff, -0x080000001, -0, 0x080000000, -(2**53), 1/0, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 0x100000001, 1.7976931348623157e308, -1/0, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-248247344*/count=406; tryItOut("\"use strict\"; s2 += o1.s2;");
/*fuzzSeed-248247344*/count=407; tryItOut("o2.h0.valueOf = (function(j) { if (j) { try { m2.delete(e = eval); } catch(e0) { } a1.forEach((function mcc_() { var fyeuao = 0; return function() { ++fyeuao; if (/*ICCD*/fyeuao % 3 == 0) { dumpln('hit!'); try { t2 = new Int8Array(b2); } catch(e0) { } try { a0.sort((function mcc_() { var pffgrw = 0; return function() { ++pffgrw; this.f2(/*ICCD*/pffgrw % 3 != 1);};})(), v2, g2.f0); } catch(e1) { } try { v1 = a2.some((function() { try { this.v1 = (g2 instanceof this.s1); } catch(e0) { } try { o0.i2 = o1.a2.keys; } catch(e1) { } v1 = Object.prototype.isPrototypeOf.call(p0, a1); return f2; })); } catch(e2) { } v1 = (o1.t2 instanceof this.e1); } else { dumpln('miss!'); try { e0 + ''; } catch(e0) { } try { g0.g0.v1 = evalcx(\"function f0(g1.p2)  { a2.unshift(h2); } \", g0); } catch(e1) { } try { print(b1); } catch(e2) { } v1 = new Number(h0); } };})()); } else { try { print(uneval(t2)); } catch(e0) { } try { a0.shift(); } catch(e1) { } try { /*MXX2*/g0.Map.prototype.keys = g2.t1; } catch(e2) { } v0 = (a2 instanceof p2); } });");
/*fuzzSeed-248247344*/count=408; tryItOut("let(e = x, w,  ) ((function(){(4277);})());");
/*fuzzSeed-248247344*/count=409; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.fround(( + x)) > Math.fround((( + Math.min((Math.pow(0x080000001, (x | 0)) | 0), (Math.fround(Math.atan2(Math.fround(x), Math.fround(x))) >>> 0))) >>> 0))) != (Math.min(Math.imul(((( + ( + Math.expm1(y))) - ( + y)) >>> 0), 0.000000000000001), Math.fround(mathy0(Math.fround(((((y | 0) - (((y << (x | 0)) | 0) | 0)) | 0) / -0x080000000)), 1.7976931348623157e308))) >>> 0)); }); testMathyFunction(mathy2, [-0x0ffffffff, 1, 42, Number.MAX_SAFE_INTEGER, 0, 0x080000001, -0x100000001, Number.MAX_VALUE, 2**53+2, 0.000000000000001, 0x080000000, -0, 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), -(2**53+2), -0x07fffffff, -1/0, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, 1/0, -0x100000000, 0x100000001, -0x080000001, 0x07fffffff, Math.PI, -0x080000000, 0/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=410; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-248247344*/count=411; tryItOut("let (z) { \u0009yield; }");
/*fuzzSeed-248247344*/count=412; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.sign(( + Math.max((Math.log2((( ! ((( ! x) >>> (( + x) >>> 0)) >>> 0)) | 0)) | 0), ( ! x))))); }); testMathyFunction(mathy1, [0/0, -(2**53+2), -0, -Number.MIN_VALUE, 42, -0x100000001, -0x100000000, 1/0, -0x080000000, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, -(2**53), -(2**53-2), Number.MAX_VALUE, 1, 0x0ffffffff, -0x0ffffffff, 0, 0.000000000000001, 0x080000001, 0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, -0x080000001, -1/0]); ");
/*fuzzSeed-248247344*/count=413; tryItOut("e1.add(h1);");
/*fuzzSeed-248247344*/count=414; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-248247344*/count=415; tryItOut("/* no regression tests found */\n/* no regression tests found */\n");
/*fuzzSeed-248247344*/count=416; tryItOut("\"use strict\"; v0 = (i1 instanceof i1);");
/*fuzzSeed-248247344*/count=417; tryItOut("mathy3 = (function(x, y) { return (((( ! (( + Math.imul(2**53-2, Math.fround(0x100000001))) ? Math.sinh(Math.fround(y)) : ( + -Number.MAX_SAFE_INTEGER))) | 0) >>> ( ~ ( + Math.atan2(( + (( + x) , Number.MIN_VALUE)), ( + x))))) | 0); }); testMathyFunction(mathy3, [-0x080000000, -(2**53), Math.PI, 0x100000000, 1, 0, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, -1/0, 2**53, 0x0ffffffff, 0x080000000, Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, 42, -(2**53-2), -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -0, 0.000000000000001, -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 1/0, 2**53-2, -0x100000000]); ");
/*fuzzSeed-248247344*/count=418; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.imul(Math.max(Math.log(0.000000000000001), mathy0(Math.max(( + Math.log2(Math.max(( + y), x))), y), x)), ((Math.atan((x || ( + ( - ((( + y) >> ( + Math.asin(x))) >>> 0))))) + ( + (((( - Math.fround(mathy1((y | 0), Math.fround(x)))) >>> 0) / (Math.fround(Math.exp(Math.fround(x))) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 2**53+2, 42, Number.MIN_VALUE, -0, 1, -0x100000001, 0x0ffffffff, -0x100000000, 0x07fffffff, -1/0, -(2**53+2), -(2**53-2), -0x080000000, 0x080000000, Number.MAX_SAFE_INTEGER, 0, 0x100000001, Number.MAX_VALUE, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 2**53-2, 0.000000000000001, 0x080000001, -(2**53), 1/0, 0/0, -0x080000001]); ");
/*fuzzSeed-248247344*/count=419; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + ( + ( + (Math.fround(Math.round(( + Math.atan2(Math.fround(-Number.MIN_SAFE_INTEGER), ( + Math.fround(( - -Number.MAX_SAFE_INTEGER))))))) | 0)))), ( + (Math.atan2(( + y), -Number.MAX_VALUE) <= Math.imul(Math.hypot(( ! ( + ( + (( + y) && ( + x))))), y), ( + ((Math.trunc(( + Math.atan2((Math.PI | 0), (x | 0)))) == (( - x) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, -Infinity, function(){}, -Infinity, function(){}, function(){}, -Infinity, -Infinity, -Infinity, function(){}, -Infinity, function(){}, function(){}, -Infinity, -Infinity, function(){}, function(){}, -Infinity, -Infinity, -Infinity]); ");
/*fuzzSeed-248247344*/count=420; tryItOut("\"use strict\"; v1 = evaluate(\"i0.send(h0);\", ({ global: g2.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 != 1), noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 43 != 21), sourceMapURL: this.s2 }))");
/*fuzzSeed-248247344*/count=421; tryItOut("\"use asm\"; switch(WeakMap.prototype|=allocationMarker()) { default: break; case /*wrap1*/(function(){ \"use strict\"; v2 = Object.prototype.isPrototypeOf.call(s0, g0.a1);return Object.prototype.toLocaleString})(): Array.prototype.unshift.call(a0, m0, h1, p0);break; if(false) m1.get(b0); else  if (Math.fround(((( + (( + Math.round(( + ( + (( + x) << ( + (( + 1/0) | x))))))) === Math.imul(Math.fround(42), Math.fround(Math.sqrt(( + -(2**53+2))))))) >>> 0) ? (( + Math.sqrt(( + x))) >>> 0) : (( ~ ( - (( ! ( + x)) >>> 0))) !== Math.fround(Math.fround(( - Math.min(Math.fround((Math.fround((Math.abs((x | 0)) | 0)) ? ( + 0x07fffffff) : Math.fround(x))), Math.sinh(1/0))))))))) {print(0.806);print(x); }break; t2 = new Int32Array(t2);break; case 7: /* no regression tests found */case window: case 6: b1 + '';case 9: case /\\1/y: for (var v of p0) { try { v2 = true; } catch(e0) { } e1.delete(v2); }case 3: a1.shift();\ni0.next();\nbreak; break; e2.add(i2);break; case 2: ;break;  }");
/*fuzzSeed-248247344*/count=422; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.acosh(Math.fround(Math.exp((Math.imul((Math.pow((y >>> 0), (x >>> 0)) | 0), (( + ( - x)) | 0)) | 0)))) % (( ! x) << (( + ( + y)) ^ ((y << y) | 0)))) && ( - Math.fround(Math.sign((( ~ ((x , x) | 0)) | 0))))); }); testMathyFunction(mathy0, [0x0ffffffff, 0x07fffffff, 42, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, -(2**53), 0x100000000, 1/0, -0x07fffffff, 0x100000001, -0, -1/0, 1, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, Number.MIN_VALUE, Math.PI, 0.000000000000001, 0x080000000, -0x100000000, 2**53-2, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=423; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(mathy4(Math.fround((Math.atan(( ! mathy4((( ! x) >>> 0), (Math.cosh((x >>> 0)) >>> 0)))) | 0)), Math.fround(( + Math.imul(((( + (((y + Number.MAX_SAFE_INTEGER) >>> 0) ? (y < x) : (Math.hypot(((Math.abs(y) >>> 0) | 0), (y | 0)) | 0))) < Math.fround(y)) | 0), Math.fround((((Math.log10((Math.hypot(y, ( + y)) >>> 0)) | 0) <= (( - (-0x07fffffff ? mathy0(y, x) : y)) | 0)) | 0))))))); }); testMathyFunction(mathy5, [-0x0ffffffff, 0.000000000000001, 0x100000000, 2**53, -(2**53-2), -0, 0/0, 2**53+2, 0, 0x0ffffffff, 0x080000000, -0x100000000, -(2**53+2), -0x080000001, 1, 0x100000001, -0x07fffffff, 0x07fffffff, 42, 0x080000001, -1/0, Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, Math.PI, -Number.MIN_VALUE, 2**53-2, -0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000001]); ");
/*fuzzSeed-248247344*/count=424; tryItOut("\"use strict\"; /*infloop*/for(e = this.__defineSetter__(\"eval\", (uneval( \"\" ))); new (x)(); x) /*RXUB*/var r = r2; var s = \"\"; print(s.replace(r, r, \"m\")); ");
/*fuzzSeed-248247344*/count=425; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[0/0, false, new Boolean(true), 0/0, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), 0/0, 0/0, new Boolean(true), 0/0, false, false, false, 0/0, 0/0, 0/0, 0/0, false, new Boolean(true), 0/0, 0/0, 0/0, 0/0, false, false, false, 0/0, new Boolean(true), 0/0, 0/0, new Boolean(true), false, false, new Boolean(true), 0/0]) { /*hhh*/function iuttde(){v0 = evaluate(\"function f0(o1)  { \\\"use strict\\\"; /*RXUB*/var r = /(?:(?:\\\\1(?:([^]*[^]+?)))|(\\\\s.|(?=(?!\\u772f))|(?:\\\\b|[\\\\d\\uf72a\\\\0-\\u66d2\\\\B]|.*))\\u71e3)/i; var s = \\\"\\\\uEADA\\\"; print(uneval(s.match(r)));  } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 29 == 10), sourceIsLazy: \"\\uEE42\", catchTermination: NaN }));}iuttde((String.prototype.small()),  '' ); }");
/*fuzzSeed-248247344*/count=426; tryItOut("\"use strict\"; ;");
/*fuzzSeed-248247344*/count=427; tryItOut("L:do print(((/*MARR*/[].filter(String.prototype.toLocaleUpperCase,  \"\" )).valueOf(\"number\"))); while((x) && 0);");
/*fuzzSeed-248247344*/count=428; tryItOut("\"use asm\"; /*ADP-2*/Object.defineProperty(o1.a2, 4, { configurable: (x % 21 == 13), enumerable: true, get: (function mcc_() { var euhdjf = 0; return function() { ++euhdjf; if (euhdjf > 6) { dumpln('hit!'); try { v0 = (s1 instanceof g2.v1); } catch(e0) { } try { this.p2 + ''; } catch(e1) { } a0.unshift(f2, (\"\\u89D7\" & Math.cbrt(2)), e0); } else { dumpln('miss!'); m2.set(m0, g1); } };})(), set: f1 });");
/*fuzzSeed-248247344*/count=429; tryItOut("(/(?=((?:$\\W|\\1)))?/gyi);new RegExp(\"\\\\3\", \"gyim\");\ni1.toString = (function mcc_() { var czinvc = 0; return function() { ++czinvc; f1(/*ICCD*/czinvc % 11 == 7);};})();\n");
/*fuzzSeed-248247344*/count=430; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0, [0], (new String('')), 0.1, ({toString:function(){return '0';}}), (new Boolean(false)), -0, NaN, (new Boolean(true)), (function(){return 0;}), '', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), true, '\\0', null, /0/, undefined, [], (new Number(0)), ({valueOf:function(){return '0';}}), '/0/', '0', (new Number(-0)), false, 1]); ");
/*fuzzSeed-248247344*/count=431; tryItOut("o2 + a0;");
/*fuzzSeed-248247344*/count=432; tryItOut("mathy0 = (function(x, y) { return ((Math.pow(Math.tan((0 >>> 0)), Math.min(((Math.imul(x, -0x07fffffff) << x) >>> 0), y)) && ( + 1/0)) !== (Math.atan2((Math.atan2(( + Math.sqrt(( + (y >> x)))), Math.hypot((Math.atan2(0/0, y) | 0), x)) >>> 0), (Math.atanh(((((( - (x | 0)) | 0) >>> 0) ** (( ~ x) >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=433; tryItOut("{v2 = (i2 instanceof f1);/*hhh*/function cnjlbl(NaN, set){v2 = g0.runOffThreadScript();}/*iii*//*RXUB*/var r = r2; var s = s0; print(uneval(s.match(r)));  }");
/*fuzzSeed-248247344*/count=434; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - ( + (( ! (Math.min(mathy2((Math.fround(mathy1(x, Math.fround(Math.hypot(y, x)))) >>> 0), x), Math.fround(( - Math.fround(Math.log2(y))))) | 0)) | 0))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), '0', [], 0, (new Boolean(true)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), NaN, false, '', (new String('')), /0/, true, (new Number(-0)), undefined, null, [0], (new Number(0)), (function(){return 0;}), objectEmulatingUndefined(), 0.1, (new Boolean(false)), 1, -0, '\\0', '/0/']); ");
/*fuzzSeed-248247344*/count=435; tryItOut("let (iyrbdb, qaztsa, a, sluusu) { ; }");
/*fuzzSeed-248247344*/count=436; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    /*FFI*/ff((((((x) < (0xbfe8090e))-((((0x18a9d4a8)-((9.671406556917033e+24) == (-4.722366482869645e+21)))>>>((Int16ArrayView[((0xfb3300a0)) >> 1])))))|0)), ((((((Infinity))))|0)), ((+(0x0))), (delete x.x), ((Float32ArrayView[2])), ((((0xff6e5cc9)))), ((+(-1.0/0.0))), ((4.722366482869645e+21)), ((-8589934593.0)), ((-9.44473296573929e+21)), ((-281474976710657.0)), ((8589934593.0)), ((-1.0)), ((0.25)), ((1048577.0)), ((-63.0)));\n    {\n      {\n        d1 = (0.0078125);\n      }\n    }\n    (Int32ArrayView[1]) = ((i0));\n    {\n      d1 = (((2199023255553.0)) * ((Float32ArrayView[(((0xd93ebcc4))) >> 2])));\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: DataView.prototype.getInt32}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0/0, 0x080000001, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0x080000000, -0x0ffffffff, 42, -0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), 1, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 0.000000000000001, 2**53, -Number.MAX_VALUE, 2**53+2, 1/0, -0x100000000, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, -0, 0x07fffffff, -0x100000001, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-248247344*/count=437; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return ( + mathy1(Math.fround((Math.fround(( + (Math.fround(( + Math.imul((-1/0 >>> 0), Math.fround(y)))) ? Math.fround(Math.fround(Math.pow((y || -Number.MIN_SAFE_INTEGER), Math.fround(mathy0(( + y), (y > ( + x))))))) : Math.fround((Math.pow(mathy0(( + (y | 0)), y), Math.imul(( + ((((y | 0) * (1/0 | 0)) | 0) ** x)), Number.MIN_VALUE)) >>> 0))))) >= Math.fround((mathy0((Math.asinh(Math.acosh(y)) | 0), (Math.fround((Math.fround(1/0) - Math.fround(( ~ (Math.max((x | 0), 2**53+2) | 0))))) | 0)) | 0)))), ((Math.sin(Math.fround(Math.fround(Math.imul((-Number.MAX_SAFE_INTEGER >>> 0), (y >>> 0))))) >>> Math.fround(( ~ ((Math.fround(x) & (Math.min(Math.fround(x), (Number.MIN_VALUE >>> 0)) >>> 0)) >>> 0)))) < ( + Math.round(Math.ceil(Math.sinh(Math.fround((x << y))))))))); }); testMathyFunction(mathy2, [2**53, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, Math.PI, 2**53-2, 42, 0x0ffffffff, -0x100000000, -0x07fffffff, -1/0, -0x080000000, 1/0, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, -(2**53-2), 0x100000000, -0x080000001, -Number.MIN_VALUE, 0x080000001, -(2**53), 0x07fffffff, -0x100000001, -0, 0/0, -(2**53+2), 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-248247344*/count=438; tryItOut("\"use strict\"; /*oLoop*/for (cbyynv = 0; cbyynv < 49 && (((Number.isFinite).call(window, (function ([y]) { })()) ? timeout(1800) : ((+ '' ) ? Math.max(-20, 11) : Math.abs(-6)))); ++cbyynv) { /*bLoop*/for (var gbvhoo = 0; gbvhoo < 13; ++gbvhoo) { if (gbvhoo % 57 == 25) { (void schedulegc(g0)); } else { print(d); }  }  } ");
/*fuzzSeed-248247344*/count=439; tryItOut("testMathyFunction(mathy1, /*MARR*/[arguments.caller, arguments.caller, 1e-81, arguments.caller, 1e-81, new Number(1), null, arguments.caller, 1e-81, arguments.caller, null, null, 1e-81,  '' , arguments.caller,  '' , 1e-81,  '' , null, new Number(1),  '' , 1e-81, 1e-81, 1e-81,  '' , arguments.caller, null, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, new Number(1), new Number(1), new Number(1), null, 1e-81, 1e-81, 1e-81, 1e-81, null,  '' , null, null, null, arguments.caller,  '' , arguments.caller, 1e-81, arguments.caller, null, 1e-81, new Number(1),  '' , arguments.caller, null, new Number(1), arguments.caller, new Number(1), null, arguments.caller,  '' ,  '' , 1e-81, 1e-81, arguments.caller, new Number(1), 1e-81, null, null, 1e-81, null, null,  '' , arguments.caller, 1e-81, arguments.caller, arguments.caller,  '' , new Number(1), new Number(1), arguments.caller, arguments.caller, arguments.caller,  '' , 1e-81, 1e-81,  '' ,  '' , 1e-81, arguments.caller, 1e-81, 1e-81, new Number(1), null, arguments.caller,  '' , arguments.caller, null,  '' , null, new Number(1), null, arguments.caller, new Number(1),  '' , new Number(1), 1e-81, null, new Number(1), null, arguments.caller, arguments.caller, 1e-81, null, new Number(1), new Number(1), new Number(1),  '' , null,  '' , null, 1e-81,  '' , new Number(1), null, null, 1e-81, null, new Number(1), arguments.caller, 1e-81,  '' , null, null, null, new Number(1),  '' , arguments.caller, new Number(1),  '' , new Number(1), arguments.caller, arguments.caller, null,  '' , 1e-81, new Number(1),  '' , 1e-81, arguments.caller,  '' , new Number(1),  '' , new Number(1), arguments.caller, arguments.caller]); ");
/*fuzzSeed-248247344*/count=440; tryItOut("\"use strict\"; v0 = (a2 instanceof v2);");
/*fuzzSeed-248247344*/count=441; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:.)|(((?=^){549755813887,})|${4,})|((\\d))(?:(?=[\\b-\\B\\S\u1d84]))((?!\\B))+/gi; var s = \"\\n\\n\\n\\n\\n\"; print(s.search(r)); ");
/*fuzzSeed-248247344*/count=442; tryItOut("\"use strict\"; a2.push(p1, m1);");
/*fuzzSeed-248247344*/count=443; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1125899906842625.0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 36028797018963970.0;\n    var i6 = 0;\n    var i7 = 0;\n    i7 = (0x869aef7e);\n    return ((0xaff01*(i7)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return ((Math.pow(Math.pow((-Number.MIN_SAFE_INTEGER >= y), x), ( + (y < (y | 0)))) ^ (Math.cos(((Math.asin(Math.fround(Math.fround(( + (x >>> 0))))) | 0) | 0)) | 0)) | 0); })}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=444; tryItOut("testMathyFunction(mathy0, [0/0, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0, -1/0, 1, 2**53-2, 42, Number.MIN_VALUE, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -(2**53+2), -0x100000000, -0x07fffffff, -0, 1/0, 0x07fffffff, -0x0ffffffff, 0x0ffffffff, 2**53+2, -0x100000001, -0x080000001, 0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), Math.PI, 0x080000001]); ");
/*fuzzSeed-248247344*/count=445; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.atan2(Math.fround((Math.fround(Math.fround(Math.min(Math.fround(y), Math.fround(( ~ Math.PI))))) !== Math.fround(x))), Math.atan2(mathy2(( + Math.min(Math.fround(x), Math.fround(0x100000001))), Math.acos(y)), Math.trunc((y | 0))))); }); testMathyFunction(mathy3, /*MARR*/[false, [1], x, x, [1], [1], false, false, false, x, [1], x, false, [1], x, [1], [1], x, x, [1], [1], false, x, false, x, false, x, x, false, x, x, [1], [1], false]); ");
/*fuzzSeed-248247344*/count=446; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul((Math.imul(( ~ Math.fround(( + ((Math.max(Math.fround(Math.fround(Math.PI)), y) && x) | 0)))), ( ~ mathy0(( + mathy0(( + x), ( + Math.imul(x, y)))), (((x ? -Number.MAX_SAFE_INTEGER : ( + (y & y))) >>> 0) ^ x)))) >>> 0), Math.fround(Math.log(Math.fround(( + (( + Math.abs((Math.fround(Math.tanh(((y > y) >>> 0))) ? -Number.MAX_SAFE_INTEGER : Math.fround((x >> x))))) ? ( + ( - (0x080000000 | 0))) : ( + ( + Math.imul(y, ( + ( - x))))))))))); }); testMathyFunction(mathy1, [({toString:function(){return '0';}}), '0', 0.1, true, '/0/', [0], (new Number(-0)), -0, [], /0/, undefined, (function(){return 0;}), ({valueOf:function(){return 0;}}), false, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), NaN, (new Boolean(false)), (new Boolean(true)), (new String('')), null, 1, '\\0', 0, (new Number(0)), '']); ");
/*fuzzSeed-248247344*/count=447; tryItOut("\"use strict\"; function f0(f1)  { return ((new RegExp(\"^\", \"\") ? ({a1:1}) : \"\\u480C\"))(f1) } ");
/*fuzzSeed-248247344*/count=448; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (0.03125);\n    return (((i1)))|0;\n    (Int32ArrayView[1]) = ((Int32ArrayView[((0xfa003d8b)) >> 2]));\n    return (((i1)+(0x2eb77502)+((-0x8000000))))|0;\n  }\n  return f; })(this, {ff: (4277)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [[], (function(){return 0;}), undefined, (new Boolean(true)), '\\0', ({valueOf:function(){return '0';}}), -0, '/0/', 0.1, ({valueOf:function(){return 0;}}), '', false, (new Number(-0)), null, (new Number(0)), '0', NaN, (new Boolean(false)), objectEmulatingUndefined(), true, (new String('')), 1, 0, [0], ({toString:function(){return '0';}}), /0/]); ");
/*fuzzSeed-248247344*/count=449; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(mathy0((( + (Math.clz32(( + -0x07fffffff)) >>> 0)) >>> 0), Math.fround((Math.min((Math.fround(((( ~ (x % y)) >>> 0) + (-0x100000000 | 0))) | 0), ((x >> (( - x) ? y : Math.fround(( ! Math.fround(y))))) | 0)) | 0)))); }); ");
/*fuzzSeed-248247344*/count=450; tryItOut("\"use strict\"; /*infloop*/for(let c = x; (makeFinalizeObserver('tenured')); ((void options('strict')))) /*vLoop*/for (var spwcfe = 0; spwcfe < 40; ++spwcfe) { var b = spwcfe; f1.__proto__ = v2; } ");
/*fuzzSeed-248247344*/count=451; tryItOut("mathy4 = (function(x, y) { return Math.fround(mathy2(Math.fround(Math.imul(Math.fround(mathy3(x, Math.clz32((( + Math.acosh((y | 0))) >>> 0)))), Math.fround(( ~ -(2**53))))), Math.fround((( + (( - (Math.min((((((0x07fffffff >>> 0) | y) >>> 0) ? 1/0 : y) >>> 0), ( - mathy3(Math.fround(Math.cbrt(( + y))), x))) | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 1.7976931348623157e308, -0, -0x07fffffff, 0, 0x100000001, 0x100000000, -1/0, -0x0ffffffff, -(2**53-2), 2**53, 0.000000000000001, -0x100000001, 0x080000001, 2**53-2, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, -(2**53+2), -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 1, -0x080000000, 0x0ffffffff, -0x080000001, 0/0, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=452; tryItOut("mathy4 = (function(x, y) { return (Math.fround((mathy3((( ! ( + Math.fround((Math.fround(y) !== Math.fround((Math.atan2(x, x) | ( + (y == x)))))))) >>> 0), (((-0x080000000 << y) >>> 0) >>> 0)) >>> 0)) % ((Math.max(( ~ ( + ( - (Math.min(x, ( + ( ~ (x >>> 0)))) >>> 0)))), ((( + Math.tan(( + -Number.MIN_VALUE))) - Math.imul((( - (2**53 >>> 0)) >>> 0), x)) | 0)) ** ( + (( + (( + ( + mathy3((0x080000000 >>> 0), (y >>> 0)))) || 0x080000000)) ? ( + Math.imul(Math.fround(Math.fround((y ** mathy3(x, 0.000000000000001)))), x)) : (x >>> 0)))) >>> 0)); }); testMathyFunction(mathy4, [0, -0x07fffffff, Number.MAX_VALUE, 0x100000000, 0x080000000, -0x080000000, 1, 0x080000001, -(2**53-2), 2**53, -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, -1/0, -0, 0/0, -(2**53), 0.000000000000001, 1/0, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 42, Math.PI, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=453; tryItOut("/*MXX3*/g1.Root.name = g1.Root.name;");
/*fuzzSeed-248247344*/count=454; tryItOut("var lpofmm = new ArrayBuffer(4); var lpofmm_0 = new Uint16Array(lpofmm); print(lpofmm);/*MXX2*/this.g2.Uint8ClampedArray = this.s2;lpofmm_0[0]this.o2 + '';o0.a1.reverse();");
/*fuzzSeed-248247344*/count=455; tryItOut("f2 + '';");
/*fuzzSeed-248247344*/count=456; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.pow(mathy0((Math.max((Math.fround(Math.expm1(y)) | 0), ((((y >>> 0) | (Math.atan(2**53-2) >>> 0)) >>> 0) | 0)) | 0), (( + y) <= Math.fround((0x080000001 === ((x >= y) >>> 0))))), (Math.fround((mathy0((y | 0), (0.000000000000001 | 0)) | 0)) / Math.fround(( + ( ~ Math.fround(Math.pow(( + y), ((mathy0((-Number.MAX_SAFE_INTEGER | 0), (x | 0)) >>> 0) >>> 0)))))))) + Math.fround(Math.tan(((Math.fround(Math.fround(mathy0(x, mathy0(Math.fround(y), (y == x))))) >>> 0) | 0)))); }); testMathyFunction(mathy1, [-0, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), 0.000000000000001, -1/0, -0x080000001, 0, 0x100000000, 42, -0x080000000, 0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 1/0, 1, -Number.MIN_VALUE, -0x100000000, -0x100000001, -Number.MAX_VALUE, 2**53, Number.MAX_VALUE, 2**53+2, Math.PI, Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0/0, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-248247344*/count=457; tryItOut("");
/*fuzzSeed-248247344*/count=458; tryItOut("mathy3 = (function(x, y) { return mathy2(Math.sinh(mathy2(Math.fround(Math.log1p(Math.fround(Math.sinh((( + (y >>> y)) % x))))), (Math.hypot((y | 0), y) | 0))), (( + ( ! Number.MIN_SAFE_INTEGER)) | 0)); }); testMathyFunction(mathy3, [0x07fffffff, -Number.MIN_VALUE, 2**53-2, -0x080000000, 0, 0/0, -Number.MAX_SAFE_INTEGER, 1, 0x080000001, -(2**53), 0x0ffffffff, -0x100000001, Number.MAX_VALUE, 0x100000000, -0x080000001, -Number.MAX_VALUE, 42, Math.PI, 1/0, -0x100000000, 2**53, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, -(2**53+2), -0x07fffffff, 0x080000000, 2**53+2, 0x100000001, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=459; tryItOut("mathy1 = (function(x, y) { return ( + mathy0((Math.pow(mathy0(y, y), (((Math.trunc(Math.max(x, y)) >>> 0) === (Math.atan2(x, ( - y)) >>> 0)) >>> 0)) & (mathy0(Math.fround(( - x)), (((((((Math.max(y, x) >>> x) >>> 0) - (y >>> 0)) | 0) & (x | 0)) | 0) >>> 0)) >>> 0)), ( + ( + mathy0((mathy0(((y * Math.sign(Math.fround(x))) > (( ~ (2**53 | 0)) | 0)), Math.atan2(0x080000001, Math.hypot(1/0, Number.MIN_SAFE_INTEGER))) >>> 0), Math.fround(Math.fround(Math.max(Math.fround((y ? (x >>> 0) : (Math.fround(Math.fround(x)) >>> 0))), (mathy0((x | 0), (Math.log2(-(2**53+2)) | 0)) | 0))))))))); }); testMathyFunction(mathy1, [0x080000001, -0x100000000, 1/0, -Number.MAX_VALUE, 2**53, -0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0/0, Math.PI, 1.7976931348623157e308, 42, 0x100000001, 1, -Number.MIN_VALUE, 0, -0x0ffffffff, 0x080000000, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, -0, Number.MIN_VALUE, -1/0, -(2**53+2), Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=460; tryItOut("h0.get = (function(j) { if (j) { try { Array.prototype.unshift.call(a0); } catch(e0) { } /*MXX2*/g2.Function.prototype.toString = h0; } else { g0.a1 = g2.r1.exec(s0); } });");
/*fuzzSeed-248247344*/count=461; tryItOut("\"use strict\"; i2.send(this.e2);");
/*fuzzSeed-248247344*/count=462; tryItOut("Object.defineProperty(this, \"t2\", { configurable: false, enumerable: (void version(170)),  get: function() {  return t1.subarray(v1, ++(x)); } });");
/*fuzzSeed-248247344*/count=463; tryItOut("/*ODP-1*/Object.defineProperty(v0, new String(\"-4\"), ({configurable: (x % 6 != 1), enumerable: (x % 5 != 2)}));");
/*fuzzSeed-248247344*/count=464; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.fround(Math.pow(( + mathy3(Math.min(((mathy4(x, (x >>> 0)) | 0) || Math.pow(x, x)), -Number.MIN_VALUE), (mathy4(((Math.sinh(Number.MIN_SAFE_INTEGER) | 0) >>> 0), (Math.min(x, x) >>> 0)) >>> 0))), (Math.cos((((Math.imul(( ! Math.fround(x)), x) ? ( + 0x080000001) : ( + x)) >>> 0) | 0)) | 0))) , Math.fround(( + Math.log10(y))))); }); testMathyFunction(mathy5, [1/0, -Number.MIN_VALUE, -0x100000000, 2**53-2, -(2**53), 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -(2**53+2), 0x080000000, 0x07fffffff, 0x080000001, -0x0ffffffff, -0, -Number.MAX_VALUE, -1/0, Number.MAX_VALUE, 42, 2**53, -0x07fffffff, 1, -0x080000001, 0.000000000000001, 0x100000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI]); ");
/*fuzzSeed-248247344*/count=465; tryItOut("v2 = r0.global;");
/*fuzzSeed-248247344*/count=466; tryItOut("\"use strict\"; s2 + o0;");
/*fuzzSeed-248247344*/count=467; tryItOut("for (var p in p0) { try { Array.prototype.shift.call(a1, g2.m1); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a1, 5, ({})); } catch(e1) { } t2 + ''; }");
/*fuzzSeed-248247344*/count=468; tryItOut("mathy4 = (function(x, y) { return Math.hypot((mathy3(Math.sqrt(Math.atanh((y | 0))), (Math.fround(y) < Math.fround(y))) > (Math.cos(Math.fround(Math.pow(Math.fround((Math.tanh((x | 0)) | 0)), Math.fround(Math.fround(Math.atan(( + Math.atanh((x >>> 0))))))))) >>> 0)), ((( ~ ((y >>> 0) > Math.fround(y))) >>> 0) < Math.fround(Math.imul(Math.fround(Math.fround(Math.clz32(Math.fround((Math.hypot((x >>> 0), ( + x)) >>> 0))))), Math.fround((mathy2(x, (( + Math.atan2(( ~ ( + Math.max(( + y), ( + y)))), y)) | 0)) | 0)))))); }); testMathyFunction(mathy4, ['\\0', 0, '0', (new Boolean(false)), (new Number(-0)), [0], objectEmulatingUndefined(), (new Number(0)), ({valueOf:function(){return 0;}}), [], -0, null, (new Boolean(true)), ({toString:function(){return '0';}}), true, '/0/', 0.1, (function(){return 0;}), NaN, false, ({valueOf:function(){return '0';}}), (new String('')), 1, '', /0/, undefined]); ");
/*fuzzSeed-248247344*/count=469; tryItOut("h0.has = (function() { try { b1 + ''; } catch(e0) { } try { /*RXUB*/var r = r2; var s = \"0_0\"; print(s.replace(r, ''));  } catch(e1) { } b1 + ''; return g0.f1; });\nthis.o2.g1 + i2;\n");
/*fuzzSeed-248247344*/count=470; tryItOut("\"use strict\"; b1 + '';");
/*fuzzSeed-248247344*/count=471; tryItOut("testMathyFunction(mathy4, [0, null, [0], (function(){return 0;}), 0.1, true, '', false, (new Boolean(false)), '0', ({valueOf:function(){return 0;}}), NaN, '\\0', (new String('')), ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return '0';}}), -0, 1, [], undefined, (new Number(0)), /0/, objectEmulatingUndefined(), (new Boolean(true)), '/0/']); ");
/*fuzzSeed-248247344*/count=472; tryItOut("v2 = this.g2.a1.length;");
/*fuzzSeed-248247344*/count=473; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=474; tryItOut("Array.prototype.pop.apply(this.a1, [h1, (4277)]);");
/*fuzzSeed-248247344*/count=475; tryItOut("g0.a0[13] = /*FARR*/[, -23, ...[], /\\D/gyim].sort((RegExp.prototype.compile).call);");
/*fuzzSeed-248247344*/count=476; tryItOut("mathy0 = (function(x, y) { return ( ! (Math.fround(Math.min(((( ~ ((( ~ (y ? ((Math.PI - y) >>> 0) : x)) | 0) >>> 0)) | 0) | 0), Math.fround(((x | 0) ^ (( - (x >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy0, [1.7976931348623157e308, 2**53, -1/0, 0x080000001, 0x0ffffffff, 0x100000001, 0x080000000, 0, -(2**53), 0.000000000000001, -0, -Number.MIN_VALUE, Math.PI, -0x100000000, -Number.MAX_VALUE, 0x07fffffff, 0/0, -0x07fffffff, -0x080000001, 42, -0x100000001, 0x100000000, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, 1]); ");
/*fuzzSeed-248247344*/count=477; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\b(?=($)+?|(\\\\B))\", \"yi\"); var s = \"1\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=478; tryItOut("\"use strict\"; Object.prototype.watch.call(o0, 7, f2);");
/*fuzzSeed-248247344*/count=479; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 1.0;\n    (Int16ArrayView[(((d3))+(((Math.pow(x, (4277)))>>>((0xffa40e91))))) >> 1]) = ((i0));\n    d1 = (-1048577.0);\n    d3 = (+(((!(0xfdc048a9))-((0xaff87f8) != (0x58bb14b3)))>>>((i0))));\n    return +(((((-1 !=  /x/g ))) % ((((d1) != (+(1.0/0.0)))))));\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[ 'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ,  'A' ,  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent), this.__defineSetter__(\"x\", encodeURIComponent),  'A' , this.__defineSetter__(\"x\", encodeURIComponent),  'A' ,  'A' ]); ");
/*fuzzSeed-248247344*/count=480; tryItOut("mathy5 = (function(x, y) { return (((((Math.acos(Math.pow((((y >>> 0) ? y : (Math.asinh(Math.fround(x)) >>> 0)) >>> 0), y)) >>> 0) - Math.min(x, Math.fround(Math.log1p(Math.fround(x))))) ** (Math.ceil((mathy1(Math.sinh(( + y)), Math.max(( + Math.ceil(( + x))), 2**53)) >= (-Number.MIN_SAFE_INTEGER * (x | 0)))) | 0)) | 0) << ((( + Math.hypot(0x080000001, 0.000000000000001)) | 0) | Math.min((( + ((x * x) >>> 0)) >>> 0), Math.pow(1, y)))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), -0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, 2**53, -0x080000000, 0.000000000000001, -1/0, Math.PI, 2**53+2, 0x100000000, 0, 0x100000001, 0/0, 42, 0x080000000, Number.MAX_VALUE, -0x100000000, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x080000001, -0, -0x100000001, 1/0, 1]); ");
/*fuzzSeed-248247344*/count=481; tryItOut("mathy3 = (function(x, y) { return (Math.trunc((Math.imul(( + Math.max(( + y), (Math.abs(Math.fround(x)) >>> 0))), (Math.max(y, (x << ( + Math.pow(y, y)))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, -0x080000000, -0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, 1, -Number.MIN_VALUE, 1/0, -(2**53), 0/0, 1.7976931348623157e308, Math.PI, 42, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, 2**53, 0x080000000, 0x100000000, 2**53-2, -0x100000000, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -(2**53+2), 0x100000001, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=482; tryItOut("testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -1/0, -0x100000001, Math.PI, 1/0, 0x0ffffffff, 2**53+2, 2**53-2, -(2**53-2), -0x07fffffff, 0x100000000, 0x100000001, -0x080000001, -Number.MAX_VALUE, -0x100000000, 42, -0x080000000, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), -Number.MAX_SAFE_INTEGER, 0, 1, 2**53, -0, 0x080000001, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=483; tryItOut("\"use strict\"; /*oLoop*/for (let zqgvdb = 0; zqgvdb < 74; ++zqgvdb) { ; } ");
/*fuzzSeed-248247344*/count=484; tryItOut("s2 += 'x';");
/*fuzzSeed-248247344*/count=485; tryItOut("/*hhh*/function mhtibq(){/* no regression tests found */}mhtibq(/*FARR*/[(p={}, (p.z = ((void shapeOf((4277)))))()), (4277), ...((eval(\"/* no regression tests found */\")) for (([[e, x, c], e, ]) in (4277)) if (x)), ({/*toXFun*/toString: (function(j) { f1(j); }), constructor: window })].filter, [this]);");
/*fuzzSeed-248247344*/count=486; tryItOut("\"use strict\"; v0 = r0.exec;");
/*fuzzSeed-248247344*/count=487; tryItOut("\"use asm\"; p0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -3.0;\n    i0 = (0xfc2c0a12);\n    i0 = (i1);\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: Object.prototype.hasOwnProperty}, new ArrayBuffer(4096));");
/*fuzzSeed-248247344*/count=488; tryItOut("print(x);function eval((x % 3 == 2) = ((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: 18, delete:  /x/ , fix: arguments.callee.caller.caller.caller, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: undefined, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; }))(-3), x) { print((4277)); } print(x);");
/*fuzzSeed-248247344*/count=489; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.clz32(( - mathy1(x, x))) || Math.atan(( + Math.max(x, ( + ( + ( + ( + ( + Math.fround(( + (x >>> 0)))))))))))); }); testMathyFunction(mathy4, [0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -(2**53-2), -0x07fffffff, -0x080000001, 1/0, 42, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 2**53-2, 2**53+2, 0.000000000000001, 0, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, -0x080000000, 0x080000000, 0/0, 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -0, -0x100000000, 0x100000001, 1, -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=490; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=491; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.sinh(Math.min(( ~ x), (( ! y) ? ( + (mathy4(x, y) | 0)) : ((y / y) ? y : x)))); }); testMathyFunction(mathy5, [-(2**53+2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 0x080000000, -0x080000001, -0x07fffffff, 2**53, Math.PI, 1.7976931348623157e308, 2**53+2, 1, -Number.MIN_VALUE, -1/0, 0x100000000, 0, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, -Number.MAX_VALUE, -(2**53), 0/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -0x080000000, 42, -0, -0x100000001, 2**53-2, 0x100000001]); ");
/*fuzzSeed-248247344*/count=492; tryItOut("mathy0 = (function(x, y) { return (Math.min((( ~ Math.fround(((Math.imul(( + ((x | 0) + (Math.pow(x, (Math.fround((x ? Math.fround(y) : Math.fround(x))) >>> 0)) | 0))), Number.MIN_SAFE_INTEGER) | 0) & (((( + ( + x)) <= Math.fround(( ~ (0x07fffffff | 0)))) >>> 0) | 0)))) | 0), ((( ! ((Math.max(Math.fround(Math.imul(x, (x ^ y))), Math.fround(Math.trunc(Math.fround((((0x100000001 | 0) ? (y | 0) : (( ! x) | 0)) | 0))))) >>> 0) >>> 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy0, [2**53, 1, Number.MIN_VALUE, 2**53+2, 0.000000000000001, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, 42, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, -1/0, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, 0/0, 0, 0x080000001, -0x080000000, -(2**53), 2**53-2, 1.7976931348623157e308, -(2**53-2), -0x100000001, 1/0, -0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=493; tryItOut("\"use strict\"; Object.defineProperty(g2, \"g0.v2\", { configurable: false, enumerable: false,  get: function() {  return g0.eval(\"e0 = new Set(g2);\"); } });t0 = new Float32Array(6);neuter(b2, \"same-data\");");
/*fuzzSeed-248247344*/count=494; tryItOut("\"use strict\"; Array.prototype.forEach.call(this.a1, f2);");
/*fuzzSeed-248247344*/count=495; tryItOut("mathy5 = (function(x, y) { return ( + Math.pow(( + mathy3((( ~ ( + ( + Math.min((x >>> 0), (x | 0))))) ? (Math.atan2(((mathy0((Math.hypot((y | 0), ( + mathy0(( + -0), ( + y)))) | 0), (x | 0)) >>> 0) | 0), (mathy0(Math.fround(x), (y | 0)) | 0)) | 0) : ((Math.atan2(( + x), Math.fround((x >>> mathy2(y, (y | 0))))) | 0) / y)), Math.fround(Math.atan2((((Math.cosh(x) >>> 0) >>> ( + (Math.log10((y >>> 0)) >>> 0))) ? (Math.round((x >>> 0)) >>> 0) : Math.sin(x)), (( - ((Math.min(-0, (x >>> 0)) >>> 0) >>> 0)) >>> 0))))), ( + Math.fround(((( - (( + Math.log2(( + ( - x)))) >>> 0)) >>> 0) << mathy0(Number.MIN_SAFE_INTEGER, ((mathy3((y | 0), (( ! x) | 0)) | 0) === ((x >>> 0) - x)))))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -Number.MIN_VALUE, 2**53, 42, -(2**53-2), 0x080000000, Math.PI, 0x100000001, -0, -0x080000000, Number.MIN_VALUE, -0x100000001, -0x080000001, 1, 0/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x100000000, -(2**53), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 2**53-2, -1/0, 1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=496; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return ( ~ ((Math.fround(( + Math.sqrt(Math.fround(Math.atan2(Math.fround(Math.fround(Math.cosh(y))), Math.tanh(0x100000001)))))) !== ( + ( ! ( + x)))) | 0)); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, 0x100000001, 1.7976931348623157e308, 0.000000000000001, -(2**53), -Number.MAX_VALUE, -(2**53-2), 0, -0x07fffffff, 1, Number.MAX_VALUE, Number.MIN_VALUE, 42, -0x0ffffffff, 1/0, -0x100000000, 2**53+2, 0x080000001, -0x080000000, 0x080000000, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), -Number.MIN_VALUE, 2**53, 0/0, 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, 2**53-2]); ");
/*fuzzSeed-248247344*/count=497; tryItOut("h2 = h2;");
/*fuzzSeed-248247344*/count=498; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.sign(Math.fround(Math.min(Math.max(0.000000000000001, (Math.max((y >>> 0), (Math.trunc(y) >>> 0)) >>> 0)), ( + Math.pow(((-Number.MIN_VALUE >>> 0) >>> (Math.sinh(x) % ( + (( + x) ? ( + -Number.MAX_SAFE_INTEGER) : ( + y))))), (mathy0(( + y), x) | 0)))))); }); ");
/*fuzzSeed-248247344*/count=499; tryItOut("(window);c = this;\nprint(x);\n");
/*fuzzSeed-248247344*/count=500; tryItOut("\"use strict\"; t1[v0] = t2;");
/*fuzzSeed-248247344*/count=501; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[ /x/ ,  /x/ , x, this, (1/0), this,  /x/ , x, x,  /x/ ,  /x/ , (1/0),  /x/ , this, this,  /x/ ,  /x/ , this, this, this, this, this, this, this, this, this, this, this, this,  /x/ ,  /x/ , x, this, x, x, x, this, x, this, this, x, this, (1/0),  /x/ ,  /x/ , this, x, (1/0), (1/0), x, x, this, x, this, (1/0),  /x/ , x,  /x/ , x, this, (1/0), x,  /x/ ,  /x/ , (1/0),  /x/ ,  /x/ , (1/0), x, this, this]) { s1 += s0; }");
/*fuzzSeed-248247344*/count=502; tryItOut("\"use strict\"; Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-248247344*/count=503; tryItOut("\"use strict\"; testMathyFunction(mathy3, ['\\0', (new Boolean(true)), (new String('')), ({valueOf:function(){return '0';}}), false, 0, '0', [0], (new Number(0)), 0.1, NaN, null, (new Number(-0)), (function(){return 0;}), true, objectEmulatingUndefined(), (new Boolean(false)), ({toString:function(){return '0';}}), 1, undefined, '/0/', '', [], ({valueOf:function(){return 0;}}), -0, /0/]); ");
/*fuzzSeed-248247344*/count=504; tryItOut("\"use strict\"; v1 = t2.length;");
/*fuzzSeed-248247344*/count=505; tryItOut("s2 = h2;");
/*fuzzSeed-248247344*/count=506; tryItOut("switch( /* Comment */(this.__defineSetter__(\"d\", x))) { case {x: [, ], y, x, c} = {w: [[{}], [[], ]], x: {x: a, y: [, {}], z: {}}, x: {(function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 32769.0;\n    (Float64ArrayView[((0xffffffff)-(i2)) >> 3]) = ((((Float32ArrayView[0])) / ((((-2147483649.0)) - ((d3))))));\n    i2 = (i1);\n    {\n      i2 = (0x54c1107c);\n    }\n    i2 = (i2);\n    d0 = (d0);\n    {\n      {\n        d0 = (+cos(((((((-1.0625)) * ((+(imul(((((0xa6cf0b5b))>>>((0xcd7f63a)))), (eval(\"let (\\u3056) \\\"\\\\uC589\\\"\", \"\\u1979\")))|0))))) * (((abs((imul((0xfb12c969), (0x888ac85))|0))|0)))))));\n      }\n    }\n    (Int8ArrayView[1]) = (-0xfb579*((Int16ArrayView[(((d3) != (-140737488355329.0))) >> 1])));\n    return +((+/*FFI*/ff(((abs((0x59cca7a7))|0)))));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)): [], y, x}, c}: break;  }");
/*fuzzSeed-248247344*/count=507; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".(?:.*?)+*?\", \"y\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-248247344*/count=508; tryItOut("/*RXUB*/var r = /(?:.[^]\\s{4}\\s+?\\t(?!$){1,3}{2}|(?=(\\d{0}|[^\\cM-\\x52\\d\u939bC]|.\\d{262143}))?)+?/gym; var s = \"\\nauuuu\\na\\na\\na\\u0009u\\na\\na\\na\\u0009\\nauuuu\\na\\na\\na\\u0009u\\na\\na\\na\\u0009\"; print(s.match(r)); ");
/*fuzzSeed-248247344*/count=509; tryItOut(";");
/*fuzzSeed-248247344*/count=510; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-(2**53), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, 1, 2**53, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -0, 0.000000000000001, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x07fffffff, -(2**53+2), -0x100000001, -0x100000000, -0x07fffffff, 1/0, 0x100000000, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -(2**53-2), -Number.MIN_VALUE, 0x100000001, Math.PI, 0, 42]); ");
/*fuzzSeed-248247344*/count=511; tryItOut("b0 + '';");
/*fuzzSeed-248247344*/count=512; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (-8388608.0);\n    i0 = ((((!(0xfb3efb87))-(i0))|0));\n    i0 = (0xfce3096e);\n    i0 = (i0);\n    (Uint32ArrayView[2]) = (0xb70d5*(0xfd7ac88f));\n    i0 = (0x2df89146);\n    return (((0xba322138)))|0;\n    (Int8ArrayView[(((((-0x8000000) ? (16777215.0) : (3.022314549036573e+23)) <= (+(1.0/0.0))) ? ((((0xf9eee156)) ^ ((0xffffffff))) >= (abs((0x42d9a184))|0)) : ((((0xead7033b))>>>((0xffffffff)))))) >> 0]) = (-(this.x << c));\n    return ((((-((+(0.0/0.0)))) <= (-3.022314549036573e+23))))|0;\n  }\n  return f; })(this, {ff: function   /x/g  (e) { \"use strict\"; return x = c } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [true, undefined, (new Number(0)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Number(-0)), [0], (new Boolean(false)), '\\0', ({valueOf:function(){return 0;}}), '0', -0, 0, 0.1, (new String('')), NaN, /0/, [], false, objectEmulatingUndefined(), null, '', (new Boolean(true)), '/0/', 1, (function(){return 0;})]); ");
/*fuzzSeed-248247344*/count=513; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f1, f2);");
/*fuzzSeed-248247344*/count=514; tryItOut("s2.toString = (function(j) { if (j) { try { e0.has(i1); } catch(e0) { } try { a0 = Array.prototype.slice.call(a0, NaN, NaN); } catch(e1) { } try { o0.v2 = r2.toString; } catch(e2) { } /*RXUB*/var r = r0; var s = s1; print(s.split(r));  } else { try { v1 = -Infinity; } catch(e0) { } try { v0 = (e2 instanceof f0); } catch(e1) { } try { t1 = new Int8Array(0); } catch(e2) { } v0 = Array.prototype.reduce, reduceRight.call(o2.a0, (function mcc_() { var gtboll = 0; return function() { ++gtboll; o0.f1(/*ICCD*/gtboll % 11 == 7);};})(), h0); } });");
/*fuzzSeed-248247344*/count=515; tryItOut("print(x);");
/*fuzzSeed-248247344*/count=516; tryItOut("\"use strict\"; (\"\\uF2FC\");");
/*fuzzSeed-248247344*/count=517; tryItOut("\"use strict\"; selectforgc(g1.o2);");
/*fuzzSeed-248247344*/count=518; tryItOut("mathy1 = (function(x, y) { return Math.min(( + Math.atan2(( + ((( + Math.max(Math.max(y, y), x)) ^ ( + (0x07fffffff << Math.pow((y >>> 0), ((Math.cos((-0 | 0)) | 0) | 0))))) >>> 0)), (( + Math.atan(Math.fround(Math.tan(Math.fround(Math.log1p(Math.fround(( ! x)))))))) >>> 0))), ((((( ~ Math.atan2(y, ((( + Math.min(Math.log1p(-1/0), (x >>> 0))) ^ (Math.imul(mathy0(x, ( + x)), (x | 0)) | 0)) >>> 0))) >>> 0) ? ((Math.pow(( ~ x), (x >>> 0)) >>> 0) >>> 0) : (Math.hypot(( + Math.hypot(mathy0(y, x), Number.MIN_SAFE_INTEGER)), Math.atan2(x, y)) >>> 0)) | 0) | 0)); }); testMathyFunction(mathy1, /*MARR*/[undefined, {}, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, {},  /x/ ]); ");
/*fuzzSeed-248247344*/count=519; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=520; tryItOut("\"use strict\"; v1 = evaluate(\"function f0(b1) this.__defineSetter__(\\\"b1\\\", (DataView.prototype.getInt8).apply)\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce:  '' , noScriptRval: (x % 18 == 1), sourceIsLazy: (x % 49 != 23), catchTermination: (x % 4 != 1) }));");
/*fuzzSeed-248247344*/count=521; tryItOut("this.m2.get(f0);");
/*fuzzSeed-248247344*/count=522; tryItOut("e0.delete(o0);");
/*fuzzSeed-248247344*/count=523; tryItOut("\"use strict\"; s0 + '';");
/*fuzzSeed-248247344*/count=524; tryItOut("\"use strict\"; /*infloop*/for(let {x: d, x} = Math.max(20, -12); (void options('strict'));  /x/  >  /x/ .__defineSetter__(\"x\", Date.UTC)) {/*hhh*/function dklplb(w, x, d, b, x =  /x/ , a, w, y = e, e, x, \u3056, b, x =  /x/ , a, w, b, x = -17, eval, b, x, c, x, x, e, NaN, x, x, let, x, x, x, x, x, x, y, d, w, \u3056, x, z, w, x, w, x, x, a, x, a = function ([y]) { }, x, x = window, \u3056, \"\\uE380\", x = length, x, w, y =  /x/g , x, y, x, \u3056 =  '' , c, window = x, delete, w){g2.g0.v1 = this.g0.r0.multiline;}/*iii*/undefined;s0 += s0; }");
/*fuzzSeed-248247344*/count=525; tryItOut("h1 = {};");
/*fuzzSeed-248247344*/count=526; tryItOut("testMathyFunction(mathy4, [-0x080000000, 1, 0.000000000000001, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, 42, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), 2**53-2, 0x080000000, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 1/0, -Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, 1.7976931348623157e308, -0, Number.MAX_VALUE, -1/0, -0x100000001, -Number.MAX_VALUE, -0x080000001, 0x100000000, 0x100000001, 0, 0/0, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=527; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.min(( + (Math.sign(( + (Math.fround(0x100000001) ? Math.fround(Math.max((Math.fround(y) == (x | 0)), y)) : Math.fround(Math.sign(1))))) >>> 0)), Math.fround(mathy0((mathy1(y, ((x | 0) << y)) !== Math.atanh(x)), Math.fround(Math.asinh(-(2**53+2)))))); }); testMathyFunction(mathy3, [(function(){return 0;}), (new Boolean(false)), 1, (new String('')), ({toString:function(){return '0';}}), '', (new Boolean(true)), objectEmulatingUndefined(), 0, [0], NaN, (new Number(0)), [], 0.1, '0', ({valueOf:function(){return '0';}}), (new Number(-0)), -0, '/0/', true, ({valueOf:function(){return 0;}}), null, false, undefined, '\\0', /0/]); ");
/*fuzzSeed-248247344*/count=528; tryItOut("\"use strict\"; print(s1);");
/*fuzzSeed-248247344*/count=529; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, ['/0/', false, NaN, ({toString:function(){return '0';}}), [], '', objectEmulatingUndefined(), (new Boolean(false)), [0], -0, null, '\\0', '0', undefined, (new Number(-0)), /0/, 1, (new String('')), (function(){return 0;}), 0, (new Boolean(true)), 0.1, (new Number(0)), ({valueOf:function(){return '0';}}), true, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-248247344*/count=530; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.fround(( + (Math.max(y, Number.MIN_SAFE_INTEGER) >>> 0))), (Math.acosh((Math.hypot((( ~ (( + y) && y)) >>> 0), Math.fround(y)) >>> 0)) | 0)); }); testMathyFunction(mathy1, [-0x080000000, 1, -(2**53), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0, -0x0ffffffff, 0x100000001, 0x100000000, -Number.MAX_VALUE, 1/0, -0x07fffffff, 0.000000000000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, -0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, 0, -0x100000001, -Number.MIN_VALUE, 0/0, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-248247344*/count=531; tryItOut("\"use strict\"; this.a1.sort((1 for (x in [])), o2.t0, o2);");
/*fuzzSeed-248247344*/count=532; tryItOut("var e =  /x/ .setUTCSeconds();print(e);");
/*fuzzSeed-248247344*/count=533; tryItOut("mathy4 = (function(x, y) { return (Math.hypot(Math.fround(Math.log10(Math.fround(mathy0((Math.sin((x | 0)) >>> ((x | 0) ? (y | 0) : (Math.pow(y, Math.fround(y)) | 0))), Math.fround(Math.atan2(y, x)))))), (( ~ ((( + (Math.fround(Math.log2((((-0x080000001 >>> 0) ? (x >>> 0) : (-Number.MAX_VALUE >>> 0)) >>> 0))) >= ( + mathy0((x && x), (x | 0))))) / ( ~ ( + ( + y)))) | 0)) >>> 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=534; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.cosh((Math.imul(Math.fround(Math.sqrt(Math.fround(((x === (x >>> 0)) ? (Math.pow(x, ((( + y) <= y) | 0)) | 0) : y)))), (Math.clz32(((x !== x) >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), (new Boolean(true)), [0], (new String('')), null, ({valueOf:function(){return 0;}}), false, (new Number(0)), '/0/', -0, /0/, NaN, '\\0', [], (function(){return 0;}), 0.1, (new Number(-0)), undefined, 0, ({valueOf:function(){return '0';}}), 1, true, objectEmulatingUndefined(), '0', '', (new Boolean(false))]); ");
/*fuzzSeed-248247344*/count=535; tryItOut("var fsqpfl = new SharedArrayBuffer(0); var fsqpfl_0 = new Uint8ClampedArray(fsqpfl); print(fsqpfl_0[0]); fsqpfl_0[0] = -28; m2 = new Map;");
/*fuzzSeed-248247344*/count=536; tryItOut("g2.a2.splice(t1, i0, g1.t2);");
/*fuzzSeed-248247344*/count=537; tryItOut("x = e1;");
/*fuzzSeed-248247344*/count=538; tryItOut("\"use strict\"; o2 + '';\n{ if (isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(); } void 0; }\n");
/*fuzzSeed-248247344*/count=539; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! Math.sqrt(( + ((Math.fround(Math.log10(Math.fround(Math.pow(x, x)))) * Math.log(Math.fround(Math.atan2((x | 0), x)))) >>> 0)))); }); ");
/*fuzzSeed-248247344*/count=540; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=541; tryItOut("mathy5 = (function(x, y) { return ( + Math.ceil((Math.trunc(((((( ! (1 | 0)) | 0) >>> 0) ? ((mathy4(0, Math.fround(( ~ Math.fround(y)))) << x) >>> 0) : Math.PI) >>> 0)) - (y | y)))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, 2**53+2, 0, Math.PI, 0x07fffffff, -0x0ffffffff, 1/0, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), Number.MIN_VALUE, -0x080000000, 2**53, -0x100000000, 0x0ffffffff, 1, 0x080000000, 0/0, -(2**53+2), 2**53-2, -Number.MAX_VALUE, 0x100000000, 0x100000001, 42, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=542; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround(((( + Math.log1p(( + ( - mathy3((y >>> 0), x))))) >= ( + (Number.MAX_VALUE | 0))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=543; tryItOut("/*ODP-3*/Object.defineProperty(s1, \"ceil\", { configurable: , enumerable: d = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: mathy0, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function () { \"use strict\"; print(x); } , keys: function() { return Object.keys(x); }, }; })((\nx)), (1 for (x in []))), writable: true, value: h1 });");
/*fuzzSeed-248247344*/count=544; tryItOut("Array.prototype.shift.apply(o0.a0, [i2, t2]);");
/*fuzzSeed-248247344*/count=545; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.cosh(Math.fround((mathy0(y, ( + Math.pow((Number.MAX_VALUE >>> 0), (( - (x >>> 0)) | 0)))) ? Math.fround(Math.round(Math.log2(( + Math.log10(x))))) : Math.fround((Math.fround((Math.atan2((x == x), y) > y)) << x))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0.000000000000001, Number.MAX_VALUE, 0x080000001, -(2**53-2), -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, -1/0, -Number.MAX_VALUE, 1, -0x100000001, Number.MIN_VALUE, 2**53-2, 0x100000000, Math.PI, 42, -(2**53+2), -0x080000001, 0x100000001, 0x07fffffff, 0/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, 0, -0]); ");
/*fuzzSeed-248247344*/count=546; tryItOut("{ void 0; void relazifyFunctions(); }");
/*fuzzSeed-248247344*/count=547; tryItOut("this.zzz.zzz;");
/*fuzzSeed-248247344*/count=548; tryItOut("o0.v1 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (d++), noScriptRval: (delete x.NaN), sourceIsLazy: true, catchTermination: (makeFinalizeObserver('tenured')) }));");
/*fuzzSeed-248247344*/count=549; tryItOut("/*tLoop*/for (let e of /*MARR*/[function(){}, -0x2D413CCC, function(){}, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, {x:3}, {x:3}, {x:3}, function(){}, {x:3}, {x:3}, -0x2D413CCC, {x:3}, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, function(){}, -0x2D413CCC, {x:3}, function(){}, function(){}, {x:3}, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, {x:3}, function(){}]) { a1 = r2.exec(g1.s0); }");
/*fuzzSeed-248247344*/count=550; tryItOut("print(((void version(180))));function x(x)new (eval)(\u0009)(window, x)Object.seal(this.g0);");
/*fuzzSeed-248247344*/count=551; tryItOut("var w = NaN &= eval ? let (b = -24)  /x/  : (({[]: {eval: {eval: {}}, z: [[]]}, a: \u3056, e: {c}} = (4277).throw(intern(/^/im)))), NaN, y, oqbkwb, w = ({__parent__:  '' }), [, ] = encodeURIComponent((4277), (x\u000c)), z, plbkmv, b = ((eval) = this < arguments), x;/*hhh*/function awecct(x = (null ^= a)){print(x);}awecct(x, this.__defineSetter__(\"x\", (function(x, y) { return 0; })));");
/*fuzzSeed-248247344*/count=552; tryItOut("this.g2.g2.v1 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=553; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MIN_VALUE, 0, -0x0ffffffff, 0/0, 0x080000001, -Number.MAX_VALUE, 42, Number.MAX_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, -0, 2**53+2, 1, 0x07fffffff, -Number.MIN_VALUE, 1/0, 2**53-2, -0x080000001, 0x080000000, 0.000000000000001, -0x080000000, -0x07fffffff, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 1.7976931348623157e308, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=554; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=555; tryItOut("");
/*fuzzSeed-248247344*/count=556; tryItOut("v1 = a0.reduce, reduceRight((function() { try { print(uneval(e0)); } catch(e0) { } e0.delete(m1); return t0; }), e1, h0);");
/*fuzzSeed-248247344*/count=557; tryItOut("m0.set(m2, m0);");
/*fuzzSeed-248247344*/count=558; tryItOut("mathy1 = (function(x, y) { return (mathy0((Math.hypot((( - (( ~ ((mathy0(x, Number.MAX_SAFE_INTEGER) ? x : Math.fround(Math.min(y, Math.fround(y)))) | 0)) >>> 0)) | 0), (Math.expm1(mathy0(y, -(2**53+2))) >>> 0)) | 0), Math.fround(( + Math.log2(Math.hypot((y | 0), Math.fround(y)))))) | 0); }); testMathyFunction(mathy1, /*MARR*/[(void 0), false, x, (void 0), x, (void 0), x, x, x, (void 0), (void 0), x, false, x, x]); ");
/*fuzzSeed-248247344*/count=559; tryItOut("\"use strict\"; if(x) /*ADP-2*/Object.defineProperty(a1, 13, { configurable: (x % 3 != 1), enumerable: (x % 4 != 2), get: (function mcc_() { var ugankt = 0; return function() { ++ugankt; if (true) { dumpln('hit!'); i1.toSource = (function(j) { f2(j); }); } else { dumpln('miss!'); print(f0); } };})(), set: (function(j) { if (j) { this.b2 = t1.buffer; } else { s0 += 'x'; } }) }); else  if ((let (d)  \"\" )) print(x);");
/*fuzzSeed-248247344*/count=560; tryItOut("\"use strict\"; i2.send(i0);");
/*fuzzSeed-248247344*/count=561; tryItOut("M:with({e: (new RegExp(\"\\\\3\", \"gym\"))}){const o2 = Object.create(i1);m2.has(b2); }");
/*fuzzSeed-248247344*/count=562; tryItOut("/*RXUB*/var r = r1; var s = \"__\\naaaaaaaa_a\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=563; tryItOut("o2.a1 = t0[3];");
/*fuzzSeed-248247344*/count=564; tryItOut("\"use strict\"; o1.v0 = evalcx(\"function f1(e0)  { \\\"use strict\\\"; ; } \", g1);\nvar kjbqdx = new ArrayBuffer(8); var kjbqdx_0 = new Int16Array(kjbqdx); t0[({valueOf: function() { g0.o1.v2 = r2.unicode;return 2; }})];\n");
/*fuzzSeed-248247344*/count=565; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n\"toString\"  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = ((i2) ? (i2) : (/*FFI*/ff((((((((0xf84016dd)+(0x63e46623))>>>((0x7fffffff) / (0x51cd41f1))))) ^ ((0xcf00f64e)*-0xd4ea8))), ((((0xa658db4a)-((0x4c459ddd))) | ((0xfac55bc8)+(0x28dd3342)))), ((((i2)+((Uint32ArrayView[4096]))) & (((0x8b55796) / (0x6404c06a))))), ((((0xf96857f4)) ^ (-0x777c9*(0x2d1d28ba)))), ((((0xf8dda6ef)) ^ ((0xfaff436e)))), (((~((-0x8000000))))))|0));\n    d1 = ((-0x8000000) ? (d1) : (d1));\n    (Int8ArrayView[((Int32ArrayView[((0x2abf3af1)-(0x5e8488ec)) >> 2])) >> 0]) = (((((!(0x74c0f09e))-(i2)) | (((0x393f75ef) != (0xe3c818e9))+(0xf9e5169e))))+(((+(-1.0/0.0)) <= ((Uint8ArrayView[0]))) ? (0x94022c17) : (!(i2))));\n    switch (((((0x67f0c7a3) >= (0x1043b510))-(0x42483a34)) & (((0xf96834e7) ? (0xc0c0b85c) : (0xb8b344a3))))) {\n    }\n    return +((((Float32ArrayView[((0xffffffff)) >> 2])) % ((NaN))));\n  }\n  return f; })(this, {ff: /*UUV1*/(e.setInt32 = Uint8ClampedArray)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [0x07fffffff, 2**53-2, -0x080000000, -0x080000001, -(2**53-2), 0, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, -0x100000000, -0, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, -1/0, 0x100000001, 0x080000001, 0.000000000000001, 1, 1/0, -(2**53), 42, 1.7976931348623157e308, -0x0ffffffff, Math.PI, -(2**53+2), -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=566; tryItOut("\"use strict\"; v2 = evalcx(\"/*RXUB*/var r = new RegExp(\\\"[^]\\\", \\\"gm\\\"); var s = \\\"\\\\n\\\"; print(r.exec(s)); \", o0.o2.g1);");
/*fuzzSeed-248247344*/count=567; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -129.0;\n    var i3 = 0;\n    var d4 = 576460752303423500.0;\n    d4 = (((16777217.0)) * ((d1)));\n    i0 = ((((Uint32ArrayView[((-0x8000000)) >> 2])) | ((((0xffffffff) ? (0xb806d8a1) : (-0x8000000)) ? (i3) : (x))+(/*FFI*/ff(((+atan2((((this).call(new RegExp(\"[^]*\", \"gym\"), window, new RegExp(\"\\\\B\", \"gym\")))), ((+abs(((d2)))))))), ((-34359738367.0)), ((((0xffffffff)) & ((0x8a25c1e5)))), ((Infinity)), ((1152921504606847000.0)), ((147573952589676410000.0)), ((-17592186044416.0)), ((-134217728.0)), ((-3.0)))|0)+((0xd8f0db1c) < (0xffffffff)))));\n    {\n      d2 = (d1);\n    }\n    {\n      i0 = (-0x8000000);\n    }\n    /*FFI*/ff(((((0xfc869590)+(!((((0xf449a38e)) << ((0x463234f7)))))) << ((0xf87a001a) % (0xe486f00e)))), ((((140737488355329.0)) % (((d4) + (2305843009213694000.0))))), ((-70368744177665.0)));\n    d2 = (-4194305.0);\n    {\n      /*FFI*/ff(((+(1.0/0.0))), ((+(0x69a45c34))), ((16383.0)), ((NaN)), ((~(-(0x815f1811)))), ((((-0x8000000)) & ((-0x8000000)))), ((+atan2(((7.555786372591432e+22)), ((65537.0))))));\n    }\n    return +(((0xf83db73c) ? (d1) : (18446744073709552000.0)));\n  }\n  return f; })(this, {ff: String.prototype.trim}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x080000000, -(2**53), 2**53, 1, 0.000000000000001, -0x07fffffff, -0x100000000, 0/0, 1/0, -1/0, -(2**53-2), -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 1.7976931348623157e308, 0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), 2**53+2, -0, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-248247344*/count=568; tryItOut("if(true) {function o2.g0.f1(t1)  { yield new 22() }  } else  if ((void options('strict_mode'))) {e0.delete(this.f0);print(p2); } else g0.offThreadCompileScript(\"this.o0 = o1.__proto__;\");");
/*fuzzSeed-248247344*/count=569; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    switch ((-0x2cc9019)) {\n      case 1:\n        i3 = (0xffe06b55);\n        break;\n      default:\n        {\n          i3 = (i3);\n        }\n    }\n    i3 = ((Array.isArray.prototype) == (((0xd263b1ea)-(i2))>>>((i3)-((((0x8cc604a))>>>((0xbf21e3cf))) == (((0xfaf85b50))>>>((0xfdffbb33))))-(i1))));\n    return +((295147905179352830000.0));\n  }\n  return f; })(this, {ff: allocationMarker()}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=570; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.trunc((Math.log2((Math.trunc(Math.imul(( ! ((2**53-2 | 0) != x)), ( ~ x))) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=571; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=572; tryItOut("let e = ({NaN: \"\\u4F1C\".prototype});print(x);");
/*fuzzSeed-248247344*/count=573; tryItOut("");
/*fuzzSeed-248247344*/count=574; tryItOut("h0.getOwnPropertyDescriptor = (function() { try { for (var p in a1) { try { for (var p in o2.s1) { try { e0.delete(g0); } catch(e0) { } try { a2.sort((function() { for (var j=0;j<1;++j) { f1(j%4==1); } }), v1); } catch(e1) { } Array.prototype.unshift.apply(a2, [g0, i1, m1, this.i0]); } } catch(e0) { } v0 = (g0 instanceof e1); } } catch(e0) { } try { /* no regression tests found */ } catch(e1) { } try { v2 = evalcx(\"function this.f2(v0)  { \\\"use strict\\\"; return x } \", g1); } catch(e2) { } a2.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) { var r0 = a10 ^ a5; print(a8); var r1 = a1 + a8; print(r0); var r2 = 2 & a5; a8 = a0 - 3; var r3 = 9 + a0; var r4 = r1 & a2; var r5 = a7 | a4; var r6 = a6 - r3; r2 = x & a8; var r7 = a9 ^ r3; print(r1); var r8 = r0 & r6; var r9 = r2 & 4; var r10 = r2 + a4; var r11 = a10 / 3; var r12 = r8 / r5; var r13 = a0 + 3; var r14 = 1 - 2; var r15 = r4 ^ 3; var r16 = r6 / r15; print(a8); r9 = r5 & r7; var r17 = r2 | 4; var r18 = 0 | 6; var r19 = 0 - 1; var r20 = r13 ^ 0; a7 = r0 ^ r16; var r21 = r4 + r3; print(a4); var r22 = r11 * 7; var r23 = 6 ^ r11; var r24 = x % r14; var r25 = r15 + r15; var r26 = a3 - r17; var r27 = a2 ^ r10; r20 = 5 / a1; var r28 = r7 & r2; r9 = r0 * a6; var r29 = r20 * a9; var r30 = r27 / 8; r21 = a2 % r28; var r31 = r29 + a7; var r32 = a2 + r10; var r33 = r18 % r1; var r34 = 2 | 7; var r35 = 7 & r32; r27 = r5 % 1; r28 = 1 / r18; a6 = r3 ^ 9; r32 = r3 & 0; var r36 = 1 / r0; var r37 = a0 ^ r7; var r38 = r3 + r8; var r39 = 6 * r22; var r40 = r32 ^ 1; var r41 = 1 & r37; var r42 = r4 & 5; print(r6); var r43 = x / 2; r28 = r37 / r9; a1 = r10 % 5; a4 = 5 % r34; var r44 = 9 | a5; var r45 = r43 * a0; var r46 = r20 - a1; r38 = r6 * r45; var r47 = r35 + a9; var r48 = a4 ^ 5; print(r30); var r49 = r45 | x; var r50 = 6 - r24; a3 = r44 + 9; var r51 = r37 + r22; var r52 = 3 - 4; r18 = 5 / r44; r46 = r14 % r32; r47 = 0 ^ 7; print(a3); var r53 = a2 & r49; var r54 = r3 ^ 9; var r55 = r49 & r23; var r56 = 4 ^ 5; var r57 = r55 | 7; var r58 = r54 * 0; var r59 = r30 / r2; var r60 = r50 % 9; var r61 = r46 % 3; var r62 = 8 * a2; var r63 = r19 ^ r57; r60 = r33 ^ r1; r47 = r38 | r14; var r64 = r51 - r23; var r65 = 6 + 9; var r66 = r8 - r26; var r67 = r41 - r63; var r68 = 0 / r48; var r69 = a8 - 0; var r70 = 7 * 9; var r71 = r49 & 0; a7 = r9 % r30; var r72 = 9 / 3; r49 = 0 ^ r46; a9 = 1 | r34; var r73 = r8 / r45; var r74 = 8 | r9; r7 = 2 - 6; var r75 = a8 * r30; r20 = r40 | r18; var r76 = r63 - r13; var r77 = 7 * r1; var r78 = r36 % 7; var r79 = r30 & r39; r18 = 9 ^ r20; r19 = r39 * 4; var r80 = r35 + r8; var r81 = r52 - 5; var r82 = r22 - r81; var r83 = r34 * 7; var r84 = 2 + 0; var r85 = r27 % r61; var r86 = r74 + r49; var r87 = r49 * 3; print(a6); var r88 = a3 % 9; r19 = r56 - 0; r87 = 4 ^ 5; var r89 = 8 * r60; a5 = 0 | a10; r50 = r76 / r43; var r90 = 9 + r5; var r91 = r80 / r81; var r92 = r15 ^ r0; var r93 = r4 ^ 7; var r94 = 7 / r5; var r95 = 8 & r72; var r96 = r22 + r11; print(r17); var r97 = 9 + 8; var r98 = 7 - a5; var r99 = r21 - 1; var r100 = r28 ^ r50; r62 = 8 % r2; var r101 = 0 % r23; print(r39); var r102 = r75 % a7; var r103 = r44 / r23; var r104 = r66 & 2; var r105 = a10 / r58; var r106 = r12 & 5; var r107 = 2 | 9; var r108 = r45 & r62; var r109 = r83 | a9; r9 = r50 - r27; r16 = r35 * 7; r100 = a7 - r10; var r110 = r96 % r62; r16 = r42 % r54; var r111 = 2 * r110; var r112 = r85 | r97; var r113 = a6 & r84; var r114 = 2 - r75; var r115 = 3 + 2; var r116 = 7 - r16; var r117 = r39 | r86; r79 = r48 % r34; var r118 = r95 * 4; var r119 = r40 % 8; var r120 = r112 - a6; var r121 = 1 - r67; var r122 = a7 / r26; var r123 = r33 % r1; var r124 = 9 / 1; var r125 = r106 % r117; var r126 = 4 % 8; var r127 = r1 / r13; var r128 = r75 & r78; var r129 = r104 * r122; var r130 = 1 % r29; print(r17); r99 = 8 & 4; var r131 = r58 * 4; var r132 = r86 * 5; r128 = r72 + 3; var r133 = r42 ^ r54; var r134 = r130 % r52; var r135 = r1 ^ r15; var r136 = r37 | 9; var r137 = r35 & r73; var r138 = 6 ^ r109; var r139 = r47 / r67; r52 = 1 ^ 9; var r140 = r53 % r31; var r141 = r52 ^ r140; r128 = r133 + r141; r101 = r51 & r35; var r142 = 6 | 0; r49 = r34 % r129; r40 = r87 & r38; var r143 = r113 & r17; var r144 = r12 & 1; var r145 = 5 % r76; var r146 = r92 + r77; var r147 = r70 & r32; var r148 = a10 & 9; var r149 = r76 - r6; var r150 = r69 * r126; r122 = r89 | r79; r106 = 8 ^ 6; var r151 = r88 + r89; var r152 = r57 * 0; var r153 = r143 + 3; print(r7); var r154 = 1 - r93; var r155 = r0 * r16; print(r47); var r156 = r78 + a6; var r157 = r35 / 1; var r158 = r133 / r143; var r159 = r35 % r40; r49 = r11 & 2; var r160 = r100 | 6; print(r43); var r161 = 0 & r110; print(r120); r123 = r101 | r122; var r162 = r136 + r105; var r163 = 9 / r96; var r164 = r59 & r36; var r165 = r129 * r28; var r166 = a10 * r44; var r167 = r46 * r164; var r168 = r66 ^ 5; var r169 = 4 & r105; var r170 = r26 % r9; var r171 = r119 + r164; r140 = r100 * r167; var r172 = r60 % a6; var r173 = r84 / 8; print(r100); var r174 = r13 & 4; r99 = 1 / 9; print(r137); var r175 = r35 - r9; var r176 = 6 & a0; var r177 = r117 - r124; var r178 = r177 | r24; r96 = r10 / r19; var r179 = r118 % r129; var r180 = r84 & r0; var r181 = 4 & 4; var r182 = 1 & 9; var r183 = 7 + r121; r181 = 2 & 5; var r184 = r111 ^ 7; return a4; })); return o2; });");
/*fuzzSeed-248247344*/count=575; tryItOut("while(( \"\" ) && 0){\u000cv2 = Object.prototype.isPrototypeOf.call(s0, m2); }");
/*fuzzSeed-248247344*/count=576; tryItOut("f1(b1);");
/*fuzzSeed-248247344*/count=577; tryItOut("\"use strict\"; (x);for (var p in i0) { try { Array.prototype.shift.call(a2); } catch(e0) { } try { o0.m0.set(g0, f1); } catch(e1) { } try { e1.delete(t1); } catch(e2) { } s0 = new String(v2); }");
/*fuzzSeed-248247344*/count=578; tryItOut("\"use strict\"; o2 = Proxy.create(h0, b1);");
/*fuzzSeed-248247344*/count=579; tryItOut("\"use strict\"; a2[(({}, x) =>  { v2 = (g0.o2.b1 instanceof t2); } ).call(allocationMarker(), )] = e1;");
/*fuzzSeed-248247344*/count=580; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-248247344*/count=581; tryItOut("mathy3 = (function(x, y) { return Math.atanh(Math.max(((( + Math.atanh(Math.clz32((( + (x | 0)) | 0)))) == ((( + 0x0ffffffff) % ( + x)) >>> 0)) >>> 0), Math.acos(Math.fround(Math.tan((((2**53-2 | 0) && -(2**53+2)) >>> 0)))))); }); ");
/*fuzzSeed-248247344*/count=582; tryItOut("\"use strict\"; e1.add(e0);");
/*fuzzSeed-248247344*/count=583; tryItOut("for (var v of v0) { try { v0 = evalcx(\"mathy2 = (function(x, y) { return ( ~ ( + mathy0(Math.fround(Math.acos((( + (Math.cosh(Math.fround(( ~ y))) << ( + mathy0(Math.tanh(x), (Math.log10(( + x)) | 0))))) | 0))), ( ~ (Math.ceil((mathy1(Math.cbrt(y), y) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [0.000000000000001, Math.PI, 1, 2**53, -(2**53-2), Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, -0, -Number.MIN_VALUE, -0x100000000, -1/0, -0x0ffffffff, -0x100000001, 0/0, -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 0x0ffffffff, 2**53-2, 1.7976931348623157e308, -0x080000001, 0x100000000, -(2**53), 0x07fffffff, -0x080000000, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -0x07fffffff, 0, Number.MIN_VALUE]); \", g1); } catch(e0) { } v0 + v1; }");
/*fuzzSeed-248247344*/count=584; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((( + ( + Math.abs(( + ((Math.fround(x) >= x) + (Math.cbrt((x >>> 0)) >>> 0)))))) , (( + (Math.sign(x) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0/0, 0x0ffffffff, -0x080000000, 0x100000001, 2**53+2, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0, 42, Math.PI, -(2**53), 2**53-2, 1/0, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0x100000000, 1, 0.000000000000001, -0x0ffffffff, 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-248247344*/count=585; tryItOut("\"use strict\"; let b =  /x/ , x = [1,,], lsvbut, d;i1.send(this.i0);");
/*fuzzSeed-248247344*/count=586; tryItOut("\"use strict\"; t0[1] = x;");
/*fuzzSeed-248247344*/count=587; tryItOut("mathy4 = (function(x, y) { return ( + (Math.pow(( + mathy2(( + Math.hypot(( + Math.pow((0.000000000000001 < y), -Number.MAX_VALUE)), ( + (Math.hypot((x | 0), (Number.MIN_SAFE_INTEGER | 0)) | 0)))), x)), (mathy1(( - (Math.ceil(x) >>> 0)), (Math.fround(( + (Math.asin(( + y)) >>> 0))) >>> 0)) | 0)) === ( + Math.min(Math.abs(y), Math.max((Math.atanh((0x080000000 >>> 0)) >>> 0), (Math.imul(Math.fround(mathy3(y, 0/0)), Math.sinh(x)) >>> 0)))))); }); testMathyFunction(mathy4, [-0x080000000, -0x100000000, -(2**53+2), -(2**53), 0x080000000, Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, -Number.MAX_VALUE, 0.000000000000001, Math.PI, 0, 2**53, Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, -0x080000001, 1, 0x100000001, 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2), 0x07fffffff, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, -1/0, 42, -0, 0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=588; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.round((( - ((Math.fround(Math.pow(Math.fround(x), (y < y))) >>> (Math.hypot(Math.exp((y | 0)), (y >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0, 2**53+2, 2**53-2, -(2**53-2), -0x0ffffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 1/0, -0, 0x0ffffffff, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 42, -(2**53+2), -1/0, 0x080000000, 1.7976931348623157e308, -0x080000001, -0x07fffffff, -0x100000000, Math.PI, 0.000000000000001, -(2**53), 0x100000001, -Number.MAX_VALUE, -0x100000001, 0x07fffffff, 2**53, -0x080000000]); ");
/*fuzzSeed-248247344*/count=589; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround(( + (( + (mathy0(((Math.fround(( ~ x)) ^ Math.atan2((x >>> 0), 1)) >>> 0), ( ! y)) >= ( + (mathy0(Number.MIN_SAFE_INTEGER, Math.max(y, x)) >>> 0)))) != ( + Math.fround(((Math.fround((((( ~ (y >>> 0)) >>> 0) >>> 0) >= -0x0ffffffff)) >>> 0) <= -(2**53-2)))))))); }); ");
/*fuzzSeed-248247344*/count=590; tryItOut("\"use strict\"; if(true) {-6;function z() { return null } return; }");
/*fuzzSeed-248247344*/count=591; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (Math.fround(( ~ Math.fround(Math.tanh(( + ((x | 0) | (Math.fround(Math.round(x)) | 0))))))) >>> 0)) << (((Math.tanh((x >>> 0)) >>> 0) ^ (Math.cos(-(2**53-2)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, 1/0, -0x0ffffffff, 0x0ffffffff, 0, -0x080000001, 1, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -1/0, -(2**53), -0x080000000, -0x100000000, 2**53, 0/0, -0, 0x080000000, Number.MAX_VALUE, 0x100000000, 0x080000001, 1.7976931348623157e308, -(2**53+2), 2**53-2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=592; tryItOut("/*RXUB*/var r = new RegExp(\"((($)(?![^]))+\\\\b+\\\\w\\\\2+?)\", \"gym\"); var s = \"\\n\\n\\n\\n\\n\\n\\udde1\\n\\n 0\\n0\\na\"; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=593; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.max(Math.asin(((( - Math.fround((y | Math.fround(Number.MIN_SAFE_INTEGER)))) | 0) ? Math.sign((Math.log1p(x) | 0)) : ((Math.hypot(( + mathy3(( + y), ( + Math.atan2(Math.fround(y), (y | 0))))), Math.fround(((x & (( + x) >>> 0)) ** ( + (x * y))))) | 0) | 0))), Math.hypot((Math.sign((0/0 | 0)) | 0), (Math.round(Math.min(Math.fround(( ~ Math.fround(x))), Number.MAX_VALUE)) >>> 0))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -Number.MAX_VALUE, -(2**53+2), 0.000000000000001, 0x0ffffffff, -0x07fffffff, 2**53+2, 0x100000000, 0, -(2**53), -(2**53-2), -1/0, -0x080000001, 42, -0x100000001, -0, -Number.MIN_VALUE, -0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, 2**53, 1/0]); ");
/*fuzzSeed-248247344*/count=594; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    {\n      d0 = (1048577.0);\n    }\n    {\n      (Float64ArrayView[4096]) = ((-32768.0));\n    }\n    d0 = (((d0)) % ((+(0x9f0865a1))));\n    switch ((((0xffffffff)*0xfffff) ^ (0x88042*((0xa90bfb55) ? (0x5e9283dc) : (0x9c542e37))))) {\n      default:\n        i1 = ((-2147483649.0) > (-1.5));\n    }\n    i1 = ((0xfd35b8e0) ? (((((i1)+(i1))>>>((0x8ad49c75)+(0x857a3e7d)-(({a1:1})))) % (((i1)-(0xfaa788fe))>>>(((((0xc632d88))>>>((0xfe2a10a6)))))))) : (i1));\n    {\n      d0 = (((d0)) % ((d0)));\n    }\n    return (((Int32ArrayView[0])))|0;\n  }\n  return f; })(this, {ff: (Math.abs((4277)))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=595; tryItOut("m0.set(v2, t0);");
/*fuzzSeed-248247344*/count=596; tryItOut("\"use strict\"; print(uneval(o1));\n(void schedulegc(g0));\n");
/*fuzzSeed-248247344*/count=597; tryItOut(" /x/g  = t0[6];");
/*fuzzSeed-248247344*/count=598; tryItOut("testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), false, (new Boolean(true)), ({toString:function(){return '0';}}), null, ({valueOf:function(){return '0';}}), '\\0', (new Boolean(false)), '/0/', objectEmulatingUndefined(), [], (new String('')), undefined, (function(){return 0;}), true, NaN, (new Number(-0)), -0, '0', 0, 0.1, (new Number(0)), [0], '', /0/, 1]); ");
/*fuzzSeed-248247344*/count=599; tryItOut("/*RXUB*/var r = new RegExp(\"($(?:$){2}|(?=(?=.))|^*)|\\\\B{0,0}\", \"gyi\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=600; tryItOut("\"use strict\"; m1.get(a2);");
/*fuzzSeed-248247344*/count=601; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=602; tryItOut("o2.i0 + '';");
/*fuzzSeed-248247344*/count=603; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.sqrt(( + ( + (( + (( + (( ~ 0.000000000000001) , Math.tan(y))) | 0)) < ( + Math.min((-0x100000000 | 0), (( ~ Math.fround(( + Number.MAX_SAFE_INTEGER))) | 0)))))))); }); ");
/*fuzzSeed-248247344*/count=604; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ( ! Math.fround(((((Math.log2(x) >>> 0) | 0) && (((Math.pow((( + ( + ( + (Math.cbrt((0.000000000000001 >>> 0)) >>> 0)))) | 0), (( - x) | 0)) | x) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, Math.PI, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 2**53, 0x0ffffffff, -Number.MIN_VALUE, 2**53+2, -(2**53+2), 0x100000001, 1/0, -0x07fffffff, 0x100000000, -(2**53), 0x07fffffff, -0x080000001, 0x080000000, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, -0, 2**53-2, 0/0, 0, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=605; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=606; tryItOut("/*RXUB*/var r = new RegExp(\"(?:$*$\\\\r{1,1}\\\\u0030|[]+?*|(?=\\\\S+)|(.)|.|(?!(.\\\\x4F{4,}(?=\\\\b${0,})?)))\", \"yi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=607; tryItOut("mathy1 = (function(x, y) { return mathy0(mathy0(( + Math.fround(Math.imul(Math.fround((Math.atan((Math.fround(Math.log10((( ! x) >>> 0))) >>> 0)) >>> 0)), Math.fround(y)))), ((Math.min(Math.fround(( ~ Math.fround((Math.fround(0x07fffffff) | 0)))), mathy0(x, Math.hypot(( + y), (x | 0)))) >>> 0) >> (((x > (( ! x) >>> 0)) >>> 0) >>> 0))), (Math.acosh((Math.fround(( ! (((0x0ffffffff % y) ? ( ~ ( ~ (1.7976931348623157e308 >>> 0))) : x) | 0))) | 0)) | 0)); }); testMathyFunction(mathy1, [2**53, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, -(2**53+2), Math.PI, -0, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 0/0, 2**53+2, -1/0, 42, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0.000000000000001, 1, -(2**53), 1/0, 0x080000001, 0x080000000, 0, -0x0ffffffff, Number.MIN_VALUE, 0x100000001, -0x080000000]); ");
/*fuzzSeed-248247344*/count=608; tryItOut("a1.push(v2, t2);function x(x, \u3056) { \"use strict\"; yield [] = []\u0009 } print(x);");
/*fuzzSeed-248247344*/count=609; tryItOut("b1 = t1.buffer;m0.get(o1.p2);");
/*fuzzSeed-248247344*/count=610; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ~ ( + Math.max(( + Math.fround((Math.fround((Math.fround(( ! x)) / ( ~ y))) !== ((Math.clz32(Math.asin((x | 0))) ? x : x) | 0)))), ( + ( ! Math.imul(Math.fround(Math.min(Math.fround(x), Math.fround(x))), y)))))); }); ");
/*fuzzSeed-248247344*/count=611; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-248247344*/count=612; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.atan2(Math.atan2(mathy1((( + ((( + Math.min((y | 0), Math.fround(-Number.MAX_VALUE))) | 0) | 0)) | 0), (42 | 0)), ( + (( + (Math.pow(Math.clz32(( + x)), ((Math.atan(x) | 0) >>> 0)) >>> 0)) * ( + x)))), (Math.atanh(((((-0x100000001 >>> 0) ? x : -0) <= ( + Math.hypot(( + Math.fround((((( - ((mathy1(y, (x >>> 0)) >>> 0) | 0)) | 0) | 0) ? ((Math.clz32((-0 >>> 0)) !== x) >>> 0) : x))), ( + (y >> Math.fround(y)))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[{}, {}, false, {}, arguments.callee, arguments.callee, false, false, new String(''), arguments.callee, {}, new String(''), new String(''), false, false, new String('')]); ");
/*fuzzSeed-248247344*/count=613; tryItOut("let (d) { g0.offThreadCompileScript(\"g0.offThreadCompileScript(\\\"v2 = -Infinity;\\\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (d % 2 == 0), catchTermination:  ''  }));\");\nthis.g2.t1 = new Uint8Array(b1);\n }/*tLoop*/for (let w of /*MARR*/[new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), new Number(1.5), new String(''), new Number(1.5), new String(''), new Number(1.5), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('')]) { /*tLoop*/for (let z of /*MARR*/[new String('q'),  /x/g , objectEmulatingUndefined(),  /x/g , \"\\u5829\", objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5),  /x/g , \"\\u5829\", new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new Number(1.5)]) { g0.offThreadCompileScript(\"\\\"\\\\uAD11\\\"\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 6 != 0), sourceIsLazy: (z % 2 == 0), catchTermination: (x % 40 != 4) })); } }");
/*fuzzSeed-248247344*/count=614; tryItOut("m1.valueOf = o1.o1.f0;var NaN = ( /x/ .unwatch(\"toGMTString\")), b, x =  /x/ , delete, oqlfxx, eval, x;/*hhh*/function mvuhsg(x){i1 = t2[14];}/*iii*/throw this;");
/*fuzzSeed-248247344*/count=615; tryItOut("Array.prototype.sort.call(a0, (function() { for (var j=0;j<39;++j) { g1.o1.f2(j%3==1); } }), (4277), g0.g0, this.o0.g0, t1)");
/*fuzzSeed-248247344*/count=616; tryItOut("mathy4 = (function(x, y) { return (Math.cbrt((( + ( ! ( + Math.fround(( + Math.fround((Math.acos((y >>> 0)) >>> 0))))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=617; tryItOut("s0 += o1.s2;");
/*fuzzSeed-248247344*/count=618; tryItOut("mathy1 = (function(x, y) { return Math.min((( ~ (( + ( ~ ( + Math.fround((Math.pow((x | 0), Number.MIN_VALUE) ? Math.fround(x) : Math.fround((Math.expm1((0x080000001 | 0)) | 0))))))) >>> 0)) >>> 0), ((Math.min((Math.pow(( + x), (x | 0)) >>> 0), Math.atan2(-Number.MAX_VALUE, ( - y))) % ( ! x)) ? (Math.fround(Math.atan2(x, ( ! (y % (( + (( + y) | (y >>> 0))) | 0))))) ** Math.fround(( + mathy0(( + x), ( + ( + ( - (y >>> 0)))))))) : mathy0(( + mathy0(( + y), ( + x))), mathy0(y, ( + (Number.MAX_VALUE | 0)))))); }); testMathyFunction(mathy1, [-(2**53), 0, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 42, -0x100000001, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, 0x100000000, 0x080000000, 0x07fffffff, -Number.MAX_VALUE, 1/0, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 0x100000001, -1/0, -(2**53+2), -0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 1, -0x07fffffff, 2**53, 2**53+2, 0/0, -0x100000000]); ");
/*fuzzSeed-248247344*/count=619; tryItOut("\"use strict\"; i0.__proto__ = g1.m0;");
/*fuzzSeed-248247344*/count=620; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan(Math.cosh(( + ( + ( + x))))); }); testMathyFunction(mathy0, [-0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, -(2**53-2), -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, 0.000000000000001, -0x080000000, 0, 0x080000001, 42, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53, 0/0, 1.7976931348623157e308, 0x100000001, 1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, Math.PI, -(2**53), -0x080000001, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=621; tryItOut("\"use strict\"; Array.prototype.push.call(g2.a2, v0, p0, g2);");
/*fuzzSeed-248247344*/count=622; tryItOut("mathy1 = (function(x, y) { return ((Math.max(((mathy0(( + Math.imul(( - y), (x | 0))), (( - (( ~ ((((2**53-2 >>> 0) ? y : (( ~ -(2**53)) >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) >>> 0) >>> 0), (mathy0((Math.fround(mathy0(x, 42)) >>> Math.hypot(Math.expm1((-0x100000001 | 0)), Math.fround(x))), Math.acos(( + ( + (Math.fround(Number.MIN_SAFE_INTEGER) == Math.fround(y)))))) >>> 0)) >>> 0) || ( + Math.tanh(Math.fround(Math.fround(mathy0((Math.exp(( + Math.pow(( + mathy0(x, 0x07fffffff)), ( + y)))) | 0), (((x >>> 0) >= (y >>> 0)) >>> 0))))))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), new Boolean(true), [], [], objectEmulatingUndefined(), new Boolean(true), [], objectEmulatingUndefined(), [], [], new Boolean(true), objectEmulatingUndefined(), [], objectEmulatingUndefined(), [], new Boolean(true), objectEmulatingUndefined(), new Boolean(true)]); ");
/*fuzzSeed-248247344*/count=623; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ~ ((((( ! Math.PI) , (( - y) | 0)) >>> 0) ? ( + Math.acosh((( + (( + x) != ( + x))) !== x))) : (( + (Math.expm1(Math.hypot(-0x080000000, y)) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[{}, 0x40000000, 0x40000000, 0x40000000, 0x40000000, {}, {}, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, {}, {}]); ");
/*fuzzSeed-248247344*/count=624; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.log2(Math.clz32((x >>> 0))) ? (((( - (mathy4(Math.imul(( + y), y), ((Math.min(Math.fround(x), (Math.log(( + x)) >>> 0)) >>> 0) >>> 0)) >>> 0)) | 0) << Math.fround(Math.imul((Math.fround(y) || ( + y)), Math.fround(0/0)))) | 0) : ((( ~ ( + ( - Math.cosh(( + (y && y)))))) | 0) == (Math.tanh(Math.fround(( ! Math.log2((x >>> 0))))) | 0))); }); testMathyFunction(mathy5, [-(2**53-2), -0x100000000, -0x080000000, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, 42, Number.MAX_VALUE, -0, 0/0, 0x080000001, -0x100000001, 1/0, 0x100000000, 0, -0x07fffffff, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 2**53-2, -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000001, 0x100000001, 0x0ffffffff, 2**53]); ");
/*fuzzSeed-248247344*/count=625; tryItOut("\"use strict\"; this.o0.o1 = o1;");
/*fuzzSeed-248247344*/count=626; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.atan2(Math.hypot(Math.fround((( - (Math.tan((Math.round((mathy1(y, x) >>> 0)) >>> 0)) >>> 0)) >>> 0)), mathy1(( + 0.000000000000001), ( + mathy0((x | 0), ( + (Math.abs((y | 0)) | 0)))))), (Math.fround(( ~ Math.min(42, Number.MAX_VALUE))) ? mathy1(Math.log2(x), ( + (Math.asinh((Math.log10((x >>> 0)) >>> 0)) > (( ~ (Math.cosh(( + ( + x))) >>> 0)) >>> 0)))) : (Math.expm1(Math.fround((y ? (0x100000001 | 0) : (x | 0)))) | 0))); }); testMathyFunction(mathy2, [-0x0ffffffff, -0, 0x080000000, 2**53, 1/0, 0x100000000, 0, 0x0ffffffff, -0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), 0x100000001, 2**53-2, Math.PI, Number.MIN_VALUE, -0x100000001, -(2**53), 42, -0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0/0, -0x080000001, 2**53+2, -0x100000000, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1]); ");
/*fuzzSeed-248247344*/count=627; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + ( - ( - x))) >>> 0); }); ");
/*fuzzSeed-248247344*/count=628; tryItOut("i2 + '';");
/*fuzzSeed-248247344*/count=629; tryItOut("testMathyFunction(mathy0, [2**53, 0x100000001, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0, -0x100000001, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), Math.PI, 42, -0x080000001, 0, 1/0, -0, 0x07fffffff, -Number.MIN_VALUE, 0/0, -0x100000000, 2**53+2]); ");
/*fuzzSeed-248247344*/count=630; tryItOut("for (var p in f2) { try { for (var v of p0) { try { (void schedulegc(g2)); } catch(e0) { } e1.has(p0); } } catch(e0) { } try { g1.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e1) { } try { this.o1.o0.m0 = new WeakMap; } catch(e2) { } a0 = arguments; }");
/*fuzzSeed-248247344*/count=631; tryItOut("\"use strict\"; for (var p in e2) { try { Array.prototype.pop.call(a2, g0.f2); } catch(e0) { } try { /*ADP-2*/Object.defineProperty(a1, 2, { configurable: true, enumerable: true, get: (function(j) { if (j) { try { v0 = (e1 instanceof a1); } catch(e0) { } for (var p in g1.t0) { print(a0); } } else { /*MXX2*/g0.Math.clz32 = h0; } }), set: (function mcc_() { var xyuntr = 0; return function() { ++xyuntr; if (/*ICCD*/xyuntr % 4 == 0) { dumpln('hit!'); try { /*RXUB*/var r = r0; var s = s1; print(s.match(r));  } catch(e0) { } try { a2.push(m0, a1); } catch(e1) { } print(uneval(h0)); } else { dumpln('miss!'); try { i2.send(v0); } catch(e0) { } try { const v1 = new Number(NaN); } catch(e1) { } for (var p in b2) { try { this.v0 = evalcx(\"(\\\"\\\\uC3D3\\\");\", g2); } catch(e0) { } try { delete h0.keys; } catch(e1) { } try { r1 = /\\B/gy; } catch(e2) { } Object.defineProperty(this, \"v2\", { configurable: true, enumerable: (this.throw(\"\\u8594\")),  get: function() {  return a0.length; } }); } } };})() }); } catch(e1) { } try { m2.has(h0); } catch(e2) { } s1 += 'x'; }");
/*fuzzSeed-248247344*/count=632; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.replace(r, /(?!\\B*?|.)|.|(?!.{1,3})|.?/gym ? s : ({/*toXFun*/toString: Array.prototype.includes }))); a = (ArrayBuffer).call(new RegExp(\"[^\\\\d\\\\B-\\\\u00E5\\\\x0E\\\\w]|[^]\\\\3+\", \"gym\"), ).watch(\"__proto__\", x.preventExtensions\u000c);");
/*fuzzSeed-248247344*/count=633; tryItOut("t0.valueOf = (function() { try { t1[1]; } catch(e0) { } try { e2 = x; } catch(e1) { } print(uneval(b0)); throw e1; });");
/*fuzzSeed-248247344*/count=634; tryItOut("\"use strict\"; window;return;");
/*fuzzSeed-248247344*/count=635; tryItOut("for (var v of m1) { try { t0[v0] = o2; } catch(e0) { } t0 = new Uint8ClampedArray(b0, 8, ({valueOf: function() { /* no regression tests found */return 6; }})); }v2 = Object.prototype.isPrototypeOf.call(o1, g0);");
/*fuzzSeed-248247344*/count=636; tryItOut("\"use strict\"; L: a0.forEach((function() { try { a1.shift(); } catch(e0) { } try { m2 + this.v1; } catch(e1) { } try { for (var p in s0) { try { i1 = new Iterator(m1); } catch(e0) { } a1.sort((function() { for (var j=0;j<11;++j) { o1.f2(j%3==1); } }), h0); } } catch(e2) { } v0 = b0.byteLength; return o2.i0; }));");
/*fuzzSeed-248247344*/count=637; tryItOut("/*vLoop*/for (let llwoiv = 0; llwoiv < 18; ++llwoiv) { let x = llwoiv; h0.get = (function mcc_() { var yeddzk = 0; return function() { ++yeddzk; if (/*ICCD*/yeddzk % 8 == 5) { dumpln('hit!'); Array.prototype.shift.call(a1); } else { dumpln('miss!'); try { Object.defineProperty(this.g1, \"t0\", { configurable: (x % 15 != 12), enumerable: false,  get: function() { m0.set(this.g0, p1); return g2.o2.t0.subarray(14); } }); } catch(e0) { } try { i2.next(); } catch(e1) { } t2.set(t1, ({valueOf: function() { (void schedulegc(g1));return 6; }})); } };})(); } ");
/*fuzzSeed-248247344*/count=638; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.fround(Math.sign(Math.fround(((Math.imul((mathy1(y, (x | 0)) | 0), (( + x) >>> 0)) >>> 0) * Math.sign(( ! x)))))), (Math.expm1(((mathy1((( ~ ( + x)) >>> 0), (Math.acosh((Math.cbrt(y) / x)) >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy2, [-0x080000000, -(2**53), -0x100000001, 2**53-2, -(2**53+2), Math.PI, 1.7976931348623157e308, -0, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, 0x080000000, -0x100000000, -1/0, -0x080000001, 1, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 0/0, 2**53+2, -Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 1/0, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=639; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot(((( - (( ! ( - /(?!.)/y)) >>> 0)) >>> 0) >>> 0), ((Math.trunc((( + Math.min(( + x), ( + Math.asin(Math.fround(-0x080000001))))) >= Number.MIN_SAFE_INTEGER)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x080000001, -0x100000001, -(2**53+2), 1/0, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 0.000000000000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0, 0/0, Math.PI, 0x0ffffffff, 2**53+2, -0, 1.7976931348623157e308, 2**53-2, -1/0, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 42, -0x080000000, -(2**53-2), 0x100000001, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=640; tryItOut(" ''  ^= null.valueOf(\"number\");a = (w = Proxy.createFunction(({/*TOODEEP*/})(\"\\u0D85\"), function(y) { \"use strict\"; yield y; this.m0.get(t1);; yield y; })) !== (x) = -26;function x() { \"use strict\"; return delete x.window } var 21 = a1.push(i0, b1, m1), a = (Math.abs(-0)), x =  /x/ , x, x, eval, w, utiquh, x;print(x);");
/*fuzzSeed-248247344*/count=641; tryItOut("\"use strict\"; print(f2);");
/*fuzzSeed-248247344*/count=642; tryItOut("print(uneval(s2));v1 = r1.multiline;");
/*fuzzSeed-248247344*/count=643; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((mathy0(Math.fround((Math.fround(mathy0(( + Math.sin(x)), x)) != (Math.atan(1/0) < Math.fround(Math.asinh(Math.fround(Math.fround((y ** (x | 0))))))))), Math.min(mathy0(Math.fround((( ~ (Number.MIN_VALUE | 0)) | 0)), Math.sign(Math.fround(y))), mathy0((Math.hypot((y | 0), (Math.atan2((x >>> 0), (x | 0)) | 0)) | 0), x))) != ( ~ Math.fround((Math.min((( + (Math.atanh(Math.fround(Math.trunc((x >>> y)))) | 0)) | 0), (1/0 | 0)) | 0)))) | 0); }); ");
/*fuzzSeed-248247344*/count=644; tryItOut("a0[5];");
/*fuzzSeed-248247344*/count=645; tryItOut("e2.has(o1);");
/*fuzzSeed-248247344*/count=646; tryItOut("with({w: ( /x/  ? this :  /x/ )}){m0.has(this.f0)\n }");
/*fuzzSeed-248247344*/count=647; tryItOut("m0.has(b2);");
/*fuzzSeed-248247344*/count=648; tryItOut("\"use strict\"; g0.v0 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=649; tryItOut("v1 = t2.byteLength;");
/*fuzzSeed-248247344*/count=650; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-248247344*/count=651; tryItOut("function shapeyConstructor(lwegke){{ /*RXUB*/var r = /(?:\\f)(?:[\\B-\\n\u0011]{3}|\\S).?{4}/gym; var s = \"\\uffec\\uffec\\n\\n\\n\\uffec\"; print(r.test(s)); print(r.lastIndex);  } delete this[\"constructor\"];Object.freeze(this);if (lwegke) Object.freeze(this);this[\"forEach\"] = 0x3FFFFFFE;this[\"__iterator__\"] = Array.prototype.entries;if () { Array.prototype.shift.call(a2); } return this; }/*tLoopC*/for (let d of /*FARR*/[]) { try{let tkrvpd = new shapeyConstructor(d); print('EETT');  '' ;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-248247344*/count=652; tryItOut("/*RXUB*/var r = x; var s = \"\\u0119\\u0119\\u0119\"; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=653; tryItOut("");
/*fuzzSeed-248247344*/count=654; tryItOut("\"use strict\"; g1.v2.toString = (function mcc_() { var jaghpd = 0; return function() { ++jaghpd; if (/*ICCD*/jaghpd % 9 == 7) { dumpln('hit!'); try { v1 = g0.runOffThreadScript(); } catch(e0) { } try { h0.iterate = f0; } catch(e1) { } try { f0 = (function() { try { /*RXUB*/var r = r2; var s = \"11\"; print(s.split(r)); print(r.lastIndex);  } catch(e0) { } this.b2 + f2; return v2; }); } catch(e2) { } o0.o0 = Object.create(x); } else { dumpln('miss!'); Object.prototype.watch.call(e2, new String(\"10\"), (function() { v0 = NaN; throw s1; })); } };})();");
/*fuzzSeed-248247344*/count=655; tryItOut("mathy5 = (function(x, y) { return (mathy3((( - Math.fround(( - (y <= Math.fround(-1/0))))) ? (( - (x | 0)) | 0) : Math.atan2(x, ( + x))), (Math.sign((Math.fround(((Math.atan(x) | 0) >> ( + 2**53+2))) >>> 0)) >>> 0)) > (mathy1((Math.fround(Math.pow((y | 0), Math.fround(y))) ? (y != x) : ( + Math.log2(((x < Math.fround(y)) >>> 0)))), (Math.atan(x) >>> 0)) / Math.atan2((Math.min(( + ( + y)), x) ? ( ! ( ~ x)) : Math.cos(x)), x))); }); testMathyFunction(mathy5, /*MARR*/[-0x2D413CCC, true, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/ , -Infinity, [1], -Infinity, [1], -0x2D413CCC, -0x2D413CCC, true,  /x/ ,  /x/ , [1], -0x2D413CCC,  /x/ , [1], -0x2D413CCC, true, true, true, [1], -0x2D413CCC, [1], -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, [1], true, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, true, -0x2D413CCC, -0x2D413CCC, true, -0x2D413CCC,  /x/ ,  /x/ , -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/ , [1], -Infinity, true, true, [1]]); ");
/*fuzzSeed-248247344*/count=656; tryItOut("mathy1 = (function(x, y) { return mathy0(( + (( ~ ( + mathy0(( + (Math.min((( + Math.max(( + -(2**53-2)), ( + y))) >>> 0), (( ~ (x | 0)) | 0)) >>> 0)), ( + Math.pow(y, y))))) | 0)), mathy0(( + Math.pow(((Math.pow(Math.fround(Math.fround(( - -0x0ffffffff))), (( ! Math.sin(y)) | 0)) | 0) >>> 0), ( ~ mathy0((-Number.MIN_SAFE_INTEGER ? x : x), (x >>> 0))))), ((( + Math.trunc(y)) >>> 0) | 0))); }); ");
/*fuzzSeed-248247344*/count=657; tryItOut("Array.prototype.splice.call(a1, NaN, 13);");
/*fuzzSeed-248247344*/count=658; tryItOut("y, x = (4277).yoyo((eval(\"v0 = b1.byteLength;\", \"\\uED95\"))), NaN = x != (yield (4277)), x, d, b, aejgwj;v0 = evalcx(\"function f2(a1)  { /*infloop*/M: for  each(let ([]) in /[^]/gim) {v2 = x;g1.h1.fix = (function mcc_() { var aonohr = 0; return function() { ++aonohr; if (/*ICCD*/aonohr % 6 == 2) { dumpln('hit!'); try { e0.has(o0.g2); } catch(e0) { } try { e1.valueOf = offThreadCompileScript; } catch(e1) { } try { o0.v0 = a2.length; } catch(e2) { } v0 = evalcx(\\\"\\\\\\\"use strict\\\\\\\"; testMathyFunction(mathy1, /*MARR*/[new String('q'), true, null]); \\\", g2); } else { dumpln('miss!'); try { v2 = a1.length; } catch(e0) { } try { i1 = new Iterator(p0, true); } catch(e1) { } i0 + ''; } };})(); } } \", g1);");
/*fuzzSeed-248247344*/count=659; tryItOut("mathy4 = (function(x, y) { return (mathy3((( + Math.abs(( + y))) ^ (((( + (mathy1(y, x) , (y | 0))) | 0) || (( - Math.fround(x)) | 0)) >>> 0)), (Math.fround((Math.fround((Math.min(Math.max(Math.fround(x), (y ? x : Math.PI)), Math.fround(( ~ x))) ** ( + (( + y) | ( + y))))) << Math.fround(Math.min(-0x080000001, 0x080000001)))) | 0)) | 0); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 1/0, 2**53, 0x080000001, -(2**53-2), Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, 1, 2**53-2, 0x100000001, -0, -(2**53), 2**53+2, 0/0, 0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0, 0.000000000000001, -0x0ffffffff, -0x080000000, -0x080000001, Number.MAX_VALUE, -(2**53+2), -1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=660; tryItOut("\"use asm\"; Object.defineProperty(this, \"s2\", { configurable: true, enumerable: (x % 39 == 37),  get: function() {  return ''; } });");
/*fuzzSeed-248247344*/count=661; tryItOut("switch(null) { default: o1.a0 = Array.prototype.slice.call(g1.a2, -2, NaN);break;  }v0 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=662; tryItOut("(null -= /(?:.){2,4}/gim);");
/*fuzzSeed-248247344*/count=663; tryItOut("g0 + '';");
/*fuzzSeed-248247344*/count=664; tryItOut("g2 + p1;");
/*fuzzSeed-248247344*/count=665; tryItOut("\"use strict\"; let {} = x && \u3056, a = (new function(y) { \"use strict\"; return (function ([y]) { })() }()), x, e = /*RXUE*//[^\\s-z\\\u6f12-\ua729].{1}.|[^]?{1,}(\\1+)++?|\\3/y.exec(\"11a1 11a1 11a1 11a1 \\u00e7\"), qhkrrg, d = ((function fibonacci(rbelqi) { /*vLoop*/for (let gkbnbj = 0; gkbnbj < 43; ++gkbnbj) { let z = gkbnbj; (this); } ; if (rbelqi <= 1) { Array.prototype.forEach.apply(a1, [f2, t1]);; return 1; } ; return fibonacci(rbelqi - 1) + fibonacci(rbelqi - 2);  })(0)), x = ({w: Uint8ClampedArray()});for (var p in g1.a0) { try { t1 = new Int16Array(b0); } catch(e0) { } try { i0.next(); } catch(e1) { } try { this.t0 = t2.subarray(6); } catch(e2) { } o2.o0.i1 = m1.get(o2); }");
/*fuzzSeed-248247344*/count=666; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ((( ! ( ! ((mathy2((y | 0), y) ? y : x) >>> 0))) | 0) ^ mathy1((Math.sqrt((Math.round(y) | 0)) | 0), ( + mathy0(y, (y >>> 0)))))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, -0, -0x0ffffffff, Number.MAX_VALUE, -(2**53), -(2**53-2), 0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x100000000, 1, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, -(2**53+2), 2**53, 0.000000000000001, Number.MIN_VALUE, -0x080000000, -0x07fffffff, 1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, 42, -0x100000001, 0x07fffffff, -0x100000000, -1/0, -0x080000001, -Number.MAX_VALUE, 0]); ");
/*fuzzSeed-248247344*/count=667; tryItOut("g2.m1.get(i0);");
/*fuzzSeed-248247344*/count=668; tryItOut("mathy0 = (function(x, y) { return Math.max((Math.log1p((Math.atanh((Math.atan((x >>> 0)) >>> 0)) | 0)) | 0), Math.fround(( + Math.tan(( + (( ! (( ~ ( + y)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [0/0, -0x080000000, 0x080000000, -0x07fffffff, -0x0ffffffff, -0, 2**53-2, Math.PI, 0x07fffffff, -0x080000001, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 2**53, 1/0, 1, 42, -0x100000001, Number.MAX_SAFE_INTEGER, -1/0, 0x080000001, -(2**53-2), -0x100000000, 0, -Number.MAX_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=669; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( + mathy2(( + mathy2(( ~ y), (x > Number.MIN_SAFE_INTEGER))), ( + ((( + Math.min(Math.fround((( + y) != x)), ( + ( + Math.sqrt(( + (Math.atan((Math.PI | 0)) | 0))))))) >>> 0) & (Math.atan(mathy1(x, x)) >>> 0))))) || (( + Math.atan2(Math.max(Math.imul(-Number.MAX_SAFE_INTEGER, Math.fround(Math.imul(( + x), x))), Math.fround((Math.trunc(y) | 0))), (Math.max((( - (y >>> 0)) >>> 0), mathy0((Math.hypot((0 >>> 0), (y >>> 0)) >>> 0), y)) | 0))) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=670; tryItOut("\"use strict\"; for(var x = new DFGTrue( '' ) in false) h1.keys = (function(j) { if (j) { try { m0.delete(m0); } catch(e0) { } try { for (var v of s0) { try { v2 = g2.runOffThreadScript(); } catch(e0) { } try { s1 += o2.s0; } catch(e1) { } try { e1 = new Set(o0.t2); } catch(e2) { } b2 = t0.buffer; } } catch(e1) { } try { v0 = -0; } catch(e2) { } o2.toString = (function() { try { i0 + ''; } catch(e0) { } try { v1 = true; } catch(e1) { } try { ; } catch(e2) { } Array.prototype.pop.apply(a1, [b1, o0]); return g1; }); } else { try { f1(v1); } catch(e0) { } try { e2.toSource = (function() { try { var f2 = Proxy.createFunction(h2, f1, f2); } catch(e0) { } try { selectforgc(o1); } catch(e1) { } a0.pop(o2); return s2; }); } catch(e1) { } for (var v of o0.g1.p2) { try { b1 + b2; } catch(e0) { } const v1 = g0.runOffThreadScript(); } } });");
/*fuzzSeed-248247344*/count=671; tryItOut("m1.has(g1.s0);");
/*fuzzSeed-248247344*/count=672; tryItOut("/*ADP-3*/Object.defineProperty(a0, v0, { configurable: true, enumerable: (x % 5 == 0), writable: false, value: g0 });");
/*fuzzSeed-248247344*/count=673; tryItOut("/*bLoop*/for (phlkku = 0; (\"\\uE87B\") && phlkku < 75; ++phlkku) { if (phlkku % 4 == 0) { /*ODP-1*/Object.defineProperty(v2, new String(\"7\"), ({get: neuter, enumerable: true})); } else { for (var p in i2) { try { o0 + ''; } catch(e0) { } try { a0[x] = o1.v1; } catch(e1) { } /*MXX3*/g1.ReferenceError.prototype.constructor = g2.ReferenceError.prototype.constructor; } }  } ");
/*fuzzSeed-248247344*/count=674; tryItOut("mathy1 = (function(x, y) { return mathy0((mathy0(( ! Math.expm1(Math.sin(Math.fround(Math.atan(y))))), ((Math.pow(( + Math.log(((Math.cos(( + -(2**53+2))) | 0) | 0))), x) * y) | 0)) >>> 0), mathy0((x , Math.fround((Math.min(x, ((( ! y) | 0) | 0)) | 0))), ((y === -Number.MAX_VALUE) ^ Math.hypot(( + (( + x) !== y)), Math.asinh((Math.fround((0x080000000 ? Math.fround(x) : Math.fround(x))) | 0)))))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, 1, 42, -0x100000000, -0x080000001, Math.PI, -Number.MIN_VALUE, 1/0, -(2**53), 0/0, Number.MIN_VALUE, 0x100000001, -(2**53+2), 2**53, -0x080000000, -0, -(2**53-2), 2**53+2, -0x07fffffff, 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-248247344*/count=675; tryItOut("\"use strict\"; delete o2.o0.h0.defineProperty;");
/*fuzzSeed-248247344*/count=676; tryItOut("\"use strict\"; a2[v1] = a1;");
/*fuzzSeed-248247344*/count=677; tryItOut("v1 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-248247344*/count=678; tryItOut("var sqdhnp = new SharedArrayBuffer(12); var sqdhnp_0 = new Float32Array(sqdhnp); sqdhnp_0[0] = -17; var sqdhnp_1 = new Float64Array(sqdhnp); sqdhnp_1[0] = -23; yield; \"\" ; for  each(var w in d) {yield this;Array.prototype.push.apply(a2, [s0]); }yield /[^]|[^\ua905]+(?!([^]{1}|[^])|[^\\s\\W]+\\d|[^8\ucc23]{0,}){4,}/ym;\u0009/(?:\\\u9d70?)\\3/gym.unwatch(\"apply\");");
/*fuzzSeed-248247344*/count=679; tryItOut("Object.defineProperty(g0, \"v1\", { configurable: false, enumerable: (new new RegExp(\"(?!([^])*?\\\\u3B66|.).|^.\\\\b|(?:[\\\\u005C\\\\s\\\\*-\\\\]+)|(?=\\u8472|.(?=^)|\\u6d5d)\\\\2+?.{8388609}\", \"y\")((\"\\uB3CF\" === y))),  get: function() {  return o0.o0.g2.eval(\"v2 = (o1.m2 instanceof t0);\"); } });");
/*fuzzSeed-248247344*/count=680; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround((Math.imul(Math.fround(Math.ceil(( + (Math.fround(Math.acos((-0x0ffffffff | 0))) > ((Math.round(( + ((y * x) >>> 0))) | (-0x07fffffff >>> 0)) >>> 0))))), ( ! ( - ( + Math.pow((((y >>> 0) ? Math.fround(x) : (x >>> 0)) >>> 0), ( + Number.MAX_SAFE_INTEGER)))))) > (Math.pow(((( ! (Math.clz32((( ~ (Math.fround(Math.exp(Math.fround(( + ( + ( + x)))))) >>> 0)) >>> 0)) | 0)) | 0) | 0), ( + Math.hypot((y | 0), Math.fround((Math.min(-Number.MAX_SAFE_INTEGER, y) >>> 0))))) | 0))); }); testMathyFunction(mathy5, /*MARR*/[ /x/ , new String('q'), ({}),  /x/ , (-1/0)]); ");
/*fuzzSeed-248247344*/count=681; tryItOut("\"use strict\"; /*infloop*/for({} = /(?!(?=[^]*?|\\D?)*)|(((?!(?!\\n)*)))/yim; (new Boolean(x,  \"\" ))(); ) i1.send(e0);");
/*fuzzSeed-248247344*/count=682; tryItOut("\"use strict\"; m1.get(o2.g2);");
/*fuzzSeed-248247344*/count=683; tryItOut("v1 = a1.length;");
/*fuzzSeed-248247344*/count=684; tryItOut("(!x);try { return (this.__defineSetter__(\"NaN\", Array.prototype.values)); } finally { let(x = (Date.prototype.getMinutes).bind( '' .eval(\"g0.v2 = (v1 instanceof p2);\")), x, gcnnsq, x =  \"\" , huzgmb) { return;} } ");
/*fuzzSeed-248247344*/count=685; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-248247344*/count=686; tryItOut("\"use strict\"; v2 = (i0 instanceof v2);");
/*fuzzSeed-248247344*/count=687; tryItOut("\"use strict\"; b0.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Uint8ArrayView[0]) = (((0xe440e56b) <= (((i0))>>>((((0xffffffff) ? (1099511627776.0) : (1.5111572745182865e+23)) <= (+(-1.0/0.0)))+((0xf9408654) ? ((0xa49442c1) < (0x263a21e4)) : ((0xffffffff) >= (0x585578c0))))))-(i0));\n    i2 = (((0x5f92f*(((-0x8000000) ? (1.0078125) : (-2097153.0)) <= (+(((0xe57aea08)) >> ((0xfccc88fb)))))) << (((-0x248ca*(i0)) & ((Int16ArrayView[4096]))) % (((i0)-((0x2ca89e5) == (0x21dd7776))) >> ((i2))))) == (0x420aee3a));\n    (Float64ArrayView[2]) = ((1.001953125));\n    i2 = ((0x2c723b00));\n    i0 = (-0x8000000);\n    return (((i0)-(0xffffffff)))|0;\n    return (((~((new (String.prototype.endsWith)() ^ Object.defineProperty(x, \u000c\"callee\", ({enumerable: new RegExp(\"([^]{0,}|\\\\w+?{0,2}\\\\3?(?:^)*?|.{3}\\\\d|.[^]{3,})\", \"gyi\")}))))) % (0xcb4ef49)))|0;\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096));");
/*fuzzSeed-248247344*/count=688; tryItOut("print(o1);");
/*fuzzSeed-248247344*/count=689; tryItOut("\"use strict\"; var hjbabv = new SharedArrayBuffer(1); var hjbabv_0 = new Float32Array(hjbabv); hjbabv_0[0] = -4; this.t1.set(t2, window);");
/*fuzzSeed-248247344*/count=690; tryItOut("mathy0 = (function(x, y) { return Math.atan2((( + Math.pow((Math.fround(( ! Number.MIN_VALUE)) <= ( - x)), ((y | 0) !== (Math.atan(((Math.fround((x >>> 0)) >>> 0) , x)) | 0)))) >>> 0), (( + ( ! ( - x))) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[-Infinity]); ");
/*fuzzSeed-248247344*/count=691; tryItOut("v1 = (m0 instanceof a1);");
/*fuzzSeed-248247344*/count=692; tryItOut("m1 = new WeakMap;");
/*fuzzSeed-248247344*/count=693; tryItOut("/*infloop*/M:for(let w; (4277); ((4277).normalize((void shapeOf( \"\" )), eval))) {((window || true)); }");
/*fuzzSeed-248247344*/count=694; tryItOut("\"use strict\"; for (var p in g0.p1) { try { g0.f2 = Proxy.createFunction(g0.h1, f1, f1); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(g2, f2); } catch(e1) { } v2 = (b2 instanceof s2); }");
/*fuzzSeed-248247344*/count=695; tryItOut("\"use strict\"; let \u3056 = 3048162340, ajvoex, NaN;(-14);");
/*fuzzSeed-248247344*/count=696; tryItOut("\"use strict\"; ;");
/*fuzzSeed-248247344*/count=697; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.pow(( + ((Math.acosh(Math.abs(y)) != (x ? x : x)) >= ( + Math.sign(y)))), ( + ( - Math.fround(Math.atan2((Math.fround(y) ? Math.atan2(x, Number.MIN_VALUE) : Math.fround((y && Math.fround(y)))), ( + ( ~ ( + y)))))))); }); testMathyFunction(mathy4, [2**53, 1/0, 0x080000001, -0x0ffffffff, -(2**53+2), 0x07fffffff, 1, 0/0, -1/0, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -0x080000000, 0.000000000000001, Math.PI, 42, -Number.MAX_VALUE, 0x080000000, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, 1.7976931348623157e308, 0, -0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-248247344*/count=698; tryItOut("a1 = arguments.callee.arguments;");
/*fuzzSeed-248247344*/count=699; tryItOut("/*MXX3*/g2.RegExp.$+ = g0.RegExp.$+;");
/*fuzzSeed-248247344*/count=700; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.log2(Math.fround(( + ( + (( - (y >>> 0)) >>> 0))))) >>> 0) >= ( - ( ! x))); }); ");
/*fuzzSeed-248247344*/count=701; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.fround(( ~ ( + ( + Math.log2(((((x | 0) ^ (((Math.fround(x) - (x >>> 0)) >>> 0) | 0)) | 0) >>> 0)))))) ^ Math.imul(Math.fround((( ~ ( + ( + (( + y) == -Number.MAX_VALUE)))) ? x : y)), Math.atanh(x))) % Math.pow(Math.clz32(-Number.MIN_SAFE_INTEGER), mathy2((((y >>> 0) ** (Math.fround((y + Math.fround(1/0))) >>> 0)) >>> 0), ( + ((( ~ ((Math.fround(y) >>> 0) >>> 0)) >>> 0) !== (Math.sign(((x >= (0x07fffffff >>> 0)) >>> 0)) != -Number.MAX_SAFE_INTEGER)))))); }); testMathyFunction(mathy3, [1, -Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, 0x100000001, Number.MAX_VALUE, -0x07fffffff, 0/0, 2**53+2, -(2**53+2), 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -(2**53), 0, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, 0x100000000, -0x080000000, 1/0, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, 0x080000001, -(2**53-2), -0x100000001, Number.MIN_VALUE, 2**53, -0, 2**53-2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=702; tryItOut("s1 = new String;");
/*fuzzSeed-248247344*/count=703; tryItOut("m2.set(h2, p0);");
/*fuzzSeed-248247344*/count=704; tryItOut("m0.valueOf = (function(j) { f1(j); });");
/*fuzzSeed-248247344*/count=705; tryItOut("/*iii*/f2 + t2;/*hhh*/function xjmjfo(x, x, x =  \"\" , \u3056, z, w, w =  '' , eval, y, x, a, e, w, b, set, y, x = eval, x, y, x, z, x, NaN, window, a, y, getter = new RegExp(\"\\\\s+(?:[^]*)+|(\\\\s){0}[\\\\S\\ude2eE\\u00d1-\\\\u1F8B]{3,}\", \"gm\"), window = /\\2*?/yim, x, d, a, x, z, window, y, x, x, x, eval, x, a, e, x =  '' , window, x, x, b, d, x, \u3056){for (var p in t1) { a1.splice(NaN, v2, v2, b2, t2); }}");
/*fuzzSeed-248247344*/count=706; tryItOut("e2.add(p1);");
/*fuzzSeed-248247344*/count=707; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var cos = stdlib.Math.cos;\n  var log = stdlib.Math.log;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Uint8ArrayView[4096]) = (((+atan2(((d0)), ((+((d1))))))));\n    {\n      d0 = ((Int32ArrayView[((imul((((((0x1b5cf2a7) ? (0xb60a12a) : (0x79be502)))>>>((/*FFI*/ff(((17179869185.0)), ((33.0)), ((-8796093022209.0)))|0)))), (0xffffffff))|0) % (abs((~((0xfa4a3bf8)+((((0xfff63eab)) ^ ((0xf808cee3)))))))|0)) >> 2]));\n    }\n    {\n      {\n        d0 = (d1);\n      }\n    }\n    {\n      d0 = (+cos(((d0))));\n    }\n    return +((+((d0))));\n    switch ((((-0x2936ad2)+(0xffffffff)+(-0x8000000)) & ((-0x8000000)))) {\n      case 1:\n        (Int16ArrayView[((Int32ArrayView[((0xd174d8e9)-((0xee808*((0x0))))-(0xfa25befe)) >> 2])) >> 1]) = ((0xbeeaf2be));\n        break;\n      case 0:\n        return +((d0));\n        break;\n      case -2:\n        d1 = ((-0x5346547) ? (d0) : (((d0)) - ((+((+(((0xfb96d3ed)) >> ((0x9da36b12)*0x9109f))))))));\n      case -3:\n        return +((d1));\n        break;\n    }\n    d0 = (+/*FFI*/ff(((d1)), ((((0xed712e0a)) | ((new (x)(new RegExp(\"(?:(?!(\\\\udaF9\\\\b){0,2}|(?:(?=^))\\\\S|\\\\b))\", \"gyi\"),  /x/g ))+(0xacdf1b55))))));\n    d0 = (+log(((d0))));\n    d1 = (((+(-1.0/0.0))) % ((+sqrt(((d1))))));\n    return +((d1));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: undefined, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { return []; }, has: (x, d) =>  { f2 = v1; } , hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: (function(x, y) { return x; }), enumerate: function() { return []; }, keys: function() { return []; }, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000001, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 42, Math.PI, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -0, 1.7976931348623157e308, 0x0ffffffff, 1/0, -(2**53+2), 0x080000000, 2**53+2, 0/0, 0.000000000000001, -0x100000000, 2**53-2, 0x100000000, -1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -0x080000000, 1, -0x080000001, -(2**53), 0x100000001, Number.MIN_VALUE, 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=708; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + Math.abs(( + Math.sqrt(Math.fround(Math.min(Math.fround(y), Math.fround(-(2**53-2)))))))) && ( - (mathy0((Math.min(( + (( ! ((Math.atan2((y | 0), (( + x) | 0)) | 0) >>> 0)) >>> 0)), (y >>> 0)) >>> 0), ((Math.atan(( + ( ~ x))) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-0x0ffffffff, 2**53-2, -Number.MIN_VALUE, 0x100000000, 0/0, 0x080000001, -1/0, -(2**53), -0x100000000, 1.7976931348623157e308, 2**53, 2**53+2, Math.PI, 0x07fffffff, -(2**53+2), 0x080000000, 0, -Number.MAX_VALUE, 0x100000001, 42, -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, Number.MAX_VALUE, 1, 1/0, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=709; tryItOut("v0 = Object.prototype.isPrototypeOf.call(p2, g2.g1.a2);");
/*fuzzSeed-248247344*/count=710; tryItOut("a1.forEach((function(j) { if (j) { try { a2.pop(g1); } catch(e0) { } try { o0.toString = f0; } catch(e1) { } try { /*ADP-3*/Object.defineProperty(a1, 1, { configurable: true, enumerable: true, writable: ([]) = x, value: p1 }); } catch(e2) { } o0 = {}; } else { try { g0.offThreadCompileScript(\"Object.defineProperty(this, \\\"v2\\\", { configurable: false, enumerable: false,  get: function() {  return evaluate(\\\"function f2(a1)  { return window } \\\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: \\n(b = Proxy.create(({/*TOODEEP*/})(15),  '' )) & this.yoyo((/*FARR*/[[,,], , 5, , ...[]].map(function  x (w) '' , this))), sourceIsLazy: false, catchTermination: true })); } });\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: new RegExp(\"(?=(?:\\u7ea2{4,})\\\\b|(?=[^]\\\\S)+)*\", \"g\"), noScriptRval: (x % 27 != 7), sourceIsLazy: false, catchTermination: WeakMap() })); } catch(e0) { } try { g2.t2 + m0; } catch(e1) { } m0.__proto__ = o1.v1; } }));");
/*fuzzSeed-248247344*/count=711; tryItOut("/*RXUB*/var r = /\\3/gyi; var s = \"\\udaf9\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=712; tryItOut("mathy5 = (function(x, y) { return (mathy0(Math.acosh(Math.cbrt(Math.min(( ~ y), y))), (mathy4(( ~ x), ( - (y | Math.max(x, y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, -(2**53), -0x0ffffffff, 1.7976931348623157e308, 42, Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, -0, 2**53, 1, -(2**53-2), -1/0, -0x080000001, 2**53-2, 0x080000001, -0x100000001, 0/0, -0x07fffffff, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 0x100000001, 2**53+2, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-248247344*/count=713; tryItOut("\"use strict\"; e = x;");
/*fuzzSeed-248247344*/count=714; tryItOut("v0 = evaluate(\"function f1(i2)  { v0 = r2.multiline; } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 == 2), sourceIsLazy: ((function fibonacci(kvgjem) { ; if (kvgjem <= 1) { ; return 1; } ; return fibonacci(kvgjem - 1) + fibonacci(kvgjem - 2);  })(7)), catchTermination: \"\\u94BB\" }));");
/*fuzzSeed-248247344*/count=715; tryItOut("testMathyFunction(mathy3, [-0x100000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, Number.MAX_VALUE, 0x07fffffff, -(2**53), -0x080000001, 1, 0, -0x080000000, 2**53-2, -1/0, -0, Math.PI, 1.7976931348623157e308, 1/0, -0x07fffffff, 0/0, -(2**53-2), 0x080000001, -0x100000001, 2**53, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 42, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, 0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=716; tryItOut("g0.a1.shift();");
/*fuzzSeed-248247344*/count=717; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.clz32(Math.fround(Math.min(( ! y), Math.fround(( ~ ((Math.max((((Math.tan((x | 0)) | 0) ** ( ~ ((x != y) >>> 0))) | 0), y) >>> 0) | 0))))))); }); ");
/*fuzzSeed-248247344*/count=718; tryItOut("mathy1 = (function(x, y) { return (( - Math.fround(( - Math.sin(Number.MIN_SAFE_INTEGER)))) >>> 0); }); testMathyFunction(mathy1, [0/0, -Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), 2**53-2, -(2**53-2), -1/0, -0x080000001, -0x0ffffffff, 0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0x07fffffff, 0x0ffffffff, 2**53, 42, -Number.MIN_VALUE, 0, -(2**53+2), 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, -0x100000001, Math.PI, 1/0]); ");
/*fuzzSeed-248247344*/count=719; tryItOut("\"use strict\"; for (var p in v2) { try { for (var v of o0) { try { g0.e0.add(o1); } catch(e0) { } try { a2.reverse(); } catch(e1) { } try { v1 = g0.runOffThreadScript(); } catch(e2) { } o1.t1[v2] = (x) = Math.hypot(undefined, -27) || (makeFinalizeObserver('tenured')); } } catch(e0) { } try { f0 = t2[9]; } catch(e1) { } try { v1 = (o2.v1 instanceof a0); } catch(e2) { } m0.has(b0); }");
/*fuzzSeed-248247344*/count=720; tryItOut("mathy5 = (function(x, y) { return ( + (( + ((Math.fround((Math.clz32((( + (Math.imul(-(2**53), (0.000000000000001 >>> 0)) == ( + (( ~ Math.fround(this)) >>> 0)))) >>> 0)) >>> 0)) ** Math.log(( ~ Math.fround(mathy0((mathy4((( ! y) >>> 0), (( + ( + ( + x))) >>> 0)) >>> 0), x))))) | 0)) ? (( ~ ( + Math.round(( - ( + Math.cos(( + (Math.min((y >>> 0), (y >>> 0)) >>> 0)))))))) >>> 0) : ( + Math.round(Math.fround((( ~ (( + ( ! 1/0)) | 0)) | 0)))))); }); ");
/*fuzzSeed-248247344*/count=721; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var tan = stdlib.Math.tan;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -8388609.0;\n    var i3 = 0;\n    var d4 = -576460752303423500.0;\n    return ((0xa7347*(i3)))|0;\n    (Float64ArrayView[4096]) = ((d4));\n    d0 = (x);\n    return ((((d4) <= (+tan(((+(-1.0/0.0))))))+((0x9506b41d))))|0;\n  }\n  return f; })(this, {ff: (window > x)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=722; tryItOut("a0.unshift(a1, t1, b0);if(true) (void schedulegc(g1));");
/*fuzzSeed-248247344*/count=723; tryItOut("\"use strict\"; /*MXX1*/o0.o0 = g2.RangeError.prototype.message;");
/*fuzzSeed-248247344*/count=724; tryItOut("v1 = g1.runOffThreadScript();");
/*fuzzSeed-248247344*/count=725; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.log10(Math.cosh(Math.log(((Math.fround(y) & (Math.fround(mathy1(Math.fround(y), y)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [(new Boolean(false)), ({toString:function(){return '0';}}), false, -0, 0.1, '', undefined, (new Number(-0)), (new Number(0)), '\\0', ({valueOf:function(){return 0;}}), null, /0/, (new Boolean(true)), true, (function(){return 0;}), 0, '0', (new String('')), NaN, objectEmulatingUndefined(), '/0/', ({valueOf:function(){return '0';}}), 1, [], [0]]); ");
/*fuzzSeed-248247344*/count=726; tryItOut("/*tLoop*/for (let x of /*MARR*/[{}, (void 0)]) { i2.send(e0); }");
/*fuzzSeed-248247344*/count=727; tryItOut("mathy0 = (function(x, y) { return Math.atan(Math.fround(Math.fround(( + Math.fround(Math.cos((( ~ (y | 0)) | 0))))))); }); testMathyFunction(mathy0, [(function(){return 0;}), '/0/', (new Boolean(true)), null, false, -0, NaN, '0', 0, '', (new String('')), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '\\0', [], objectEmulatingUndefined(), undefined, 1, (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(false)), 0.1, /0/, (new Number(0)), true, [0]]); ");
/*fuzzSeed-248247344*/count=728; tryItOut("\"use asm\"; print(-21);");
/*fuzzSeed-248247344*/count=729; tryItOut("/*vLoop*/for (let wnvynf = 0; wnvynf < 27; ++wnvynf) { var c = wnvynf; /*MXX1*/o0 = g2.Math.imul; } ");
/*fuzzSeed-248247344*/count=730; tryItOut("/*MXX3*/g0.Function.prototype.caller = g0.Function.prototype.caller;yield x;");
/*fuzzSeed-248247344*/count=731; tryItOut("testMathyFunction(mathy0, /*MARR*/[new String(''), new String(''), new String('q'), false, false, new String('q'), new String(''), false, new String('q'), new String(''), new String('q'), new Boolean(true), new String(''), new String(''), new String(''), new String(''), new String('q'), new Boolean(true), new Boolean(true), false, new Boolean(true), new String('q'), new String(''), false, false, false, new String('q'), false, new String('q'), new String(''), false, false, false, false, false, new Boolean(true), false, new Boolean(true), new String(''), new Boolean(true), false, new Boolean(true), new String(''), new String(''), new String('q'), new Boolean(true), new String(''), new String('q'), new Boolean(true), false, new String(''), new String(''), new String(''), new Boolean(true), false, new Boolean(true), new String(''), false, false, new String(''), new String('q'), new Boolean(true), false, false, new String('q'), new String(''), new String('q'), false, false, new Boolean(true), false, new String('')]); ");
/*fuzzSeed-248247344*/count=732; tryItOut("\"use strict\"; /* no regression tests found */Array.prototype.sort.apply(a1, [Date.prototype.setUTCDate.bind(m0), x, Math.min(-9, (y = ( /x/  >>>= \"\\uA849\" - (makeFinalizeObserver('tenured')) <<= ()))), p2, o2, m0, f1, g1, this.p0, o0.a2, Math.round(let (e = []) [[1]]) ** x, a0]);");
/*fuzzSeed-248247344*/count=733; tryItOut("\"use strict\"; /*vLoop*/for (var wtcvoi = 0; wtcvoi < 70; SimpleObject(), ++wtcvoi) { const y = wtcvoi; g0 = this; } ");
/*fuzzSeed-248247344*/count=734; tryItOut("\"use strict\"; /*MXX1*/o0 = this.g1.Date.prototype.getMonth;");
/*fuzzSeed-248247344*/count=735; tryItOut("print(12);\nObject.prototype.unwatch.call(t0, \"__iterator__\");function x()\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    {\n      d0 = (d0);\n    }\n    d1 = (d0);\nprint(/*FARR*/[ /x/ , ...[], , ...[], ...[]].filter);    d0 = (+atan2(((-((Float64ArrayView[2])))), (((Infinity) + (1.0)))));\n    return (((0xffffffff)))|0;\n  }\n  return f;;\n");
/*fuzzSeed-248247344*/count=736; tryItOut("((4277));");
/*fuzzSeed-248247344*/count=737; tryItOut("o2 = new Object;");
/*fuzzSeed-248247344*/count=738; tryItOut("i0.send(h1);v0 = g2.runOffThreadScript();function w(x) { yield Math.pow(window, -12) } {/*MXX3*/g2.TypeError.name = g1.TypeError.name; }\n/*bLoop*/for (let fjsfcs = 0; fjsfcs < 129; ++fjsfcs) { if (fjsfcs % 58 == 34) { z; } else { /*tLoop*/for (let d of /*MARR*/[x, new String('q'), new String('q'), new String('q'), x, new Number(1.5), (void 0), x, x, (void 0), (void 0), new Number(1.5)]) { return; } }  } \nfunction x(x, x) { return (4277).anchor() } o2.e2 + '';");
/*fuzzSeed-248247344*/count=739; tryItOut("testMathyFunction(mathy1, [-1/0, 0x07fffffff, -0x080000001, -(2**53), -(2**53-2), 0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -Number.MAX_VALUE, 0x100000001, 1/0, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, 1, -0x100000000, 2**53-2, 0x080000001, 0, Number.MIN_VALUE, 42, 2**53, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-248247344*/count=740; tryItOut("s2 = '';");
/*fuzzSeed-248247344*/count=741; tryItOut("f2(g2.b0);");
/*fuzzSeed-248247344*/count=742; tryItOut("let x = (yield ([])), y = this.__defineSetter__(\"e\", q => q), aergmz, window, oxnvni, \u3056 = x, a, swmtaz;if((x % 4 == 1)) {print(x);throw let (a = /(?=(?:(?=(?=[^\\W\\wr\\t-\\r])+?){0}))/gim)  /x/ ; }");
/*fuzzSeed-248247344*/count=743; tryItOut("\"use strict\"; /*infloop*/for(let a; /*UUV1*/(x.setMinutes = function(y) { return /(?=.)/im }); /*MARR*/[(void 0), null, (void 0), new String('q'), (void 0), (void 0), x, -Infinity, x, (void 0), null, -Infinity, x, x, null, -Infinity, null, -Infinity, null, -Infinity, (void 0), -Infinity, -Infinity, -Infinity, x, null, -Infinity, x, (void 0), new String('q'), (void 0), -Infinity, null, null, x, null, (void 0), (void 0), -Infinity, new String('q'), (void 0), -Infinity, (void 0), null, new String('q'), x, x, new String('q'), -Infinity, null, (void 0), x, -Infinity, new String('q'), new String('q'), -Infinity, -Infinity, x, x, -Infinity, (void 0), null, (void 0), -Infinity, x, null, -Infinity, new String('q'), (void 0), -Infinity, x, new String('q'), x, (void 0), null, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, (void 0), null, null, new String('q'), -Infinity, -Infinity, x, (void 0), null, new String('q'), -Infinity, (void 0), -Infinity, null, (void 0), x, new String('q'), new String('q'), x, (void 0), (void 0), new String('q'), new String('q'), x, -Infinity, x, new String('q'), null, x, null, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, (void 0), (void 0), x, -Infinity, -Infinity, null, (void 0), (void 0), new String('q'), (void 0), null].map((let (e=eval) e), (( - (x >>> 0))))) v0 = (e1 instanceof o1);print( /x/g );");
/*fuzzSeed-248247344*/count=744; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=745; tryItOut("mathy3 = (function(x, y) { return ( ~ ( ! (((((Math.abs(Math.sign(Math.atan2(( + -0x100000000), ( + y)))) | 0) | 0) | ((x === ( + y)) >>> 0)) | 0) >>> Math.trunc((x ? x : mathy2(x, x)))))); }); testMathyFunction(mathy3, [-(2**53), 1/0, -(2**53-2), -0x100000001, 2**53+2, 2**53-2, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, -Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, -0x07fffffff, Math.PI, -1/0, 42, -0, -0x080000001, Number.MAX_VALUE, -0x080000000, -(2**53+2), 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 0/0, 2**53, 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=746; tryItOut("\"use asm\"; ;");
/*fuzzSeed-248247344*/count=747; tryItOut("for (var v of h1) { o2 = i0; }");
/*fuzzSeed-248247344*/count=748; tryItOut("mathy0 = (function(x, y) { return (Math.hypot((Math.fround(( - Math.atan2((Math.atan2((Math.sqrt(Math.pow(x, ( + (( + y) <= ( + y))))) >>> 0), (x >>> 0)) >>> 0), Math.fround((Math.fround(Math.fround(Math.cbrt(y))) === Math.fround(( ~ y))))))) >>> 0), (Math.atan2((Math.fround(Math.fround(Math.atan((( ~ (y | 0)) | 0)))) / ((Math.acosh((( ~ ( + ( - Math.fround(y)))) | 0)) | 0) | 0)), ( ~ Math.atanh(Math.fround(( ~ Math.fround(y)))))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=749; tryItOut("e2.delete(e0);");
/*fuzzSeed-248247344*/count=750; tryItOut("\"use strict\"; print(i1);");
/*fuzzSeed-248247344*/count=751; tryItOut("p1 + '';");
/*fuzzSeed-248247344*/count=752; tryItOut("\"use strict\"; for (var p in v0) { try { /*RXUB*/var r = this.r0; var s =  '' ; print(r.exec(s));  } catch(e0) { } v2 = evalcx(\"\\\"use strict\\\"; mathy5 = (function(x, y) { \\\"use strict\\\"; return ((((( + (Math.fround(( + x)) | 0)) || (Math.log1p(x) ? mathy0(-0x07fffffff, ( + x)) : Math.log(-Number.MIN_VALUE))) | 0) % (Math.sqrt((Math.fround((y ** -Number.MIN_SAFE_INTEGER)) >> y)) | 0)) - (Math.hypot(Math.hypot(y, y), mathy4((( ~ (Math.exp(y) >>> 0)) >>> 0), (y & y))) >>> 0)); }); testMathyFunction(mathy5, [0x080000000, -0x100000001, 1, -0x080000001, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, -(2**53-2), 2**53+2, 0/0, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, -(2**53), -(2**53+2), 0, -0x100000000, -0x080000000, -1/0, 42, -Number.MAX_VALUE, 2**53-2, 0x080000001, 2**53, 0.000000000000001]); \", g0); }\n{ if (!isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }\nprint((new function(y) { \"use strict\"; a1[17]; }().watch(\"length\", function (x, NaN, c, c, a = new RegExp(\"\\uc03e|\\\\b\\n$..*??(\\\\w|\\\\d+?)\", \"y\"), y = /\\3*/im, c, y, null, \u3056, \u3056, window =  /x/ , x, eval, b, NaN, x, eval, x, x, e = -22, eval, x, x, \u3056 = eval, NaN, e, x, NaN, x = new RegExp(\"(?:\\\\u00b2+?|\\u0dda[\\\\u28e9\\\\\\ubd58]|[\\\\D\\\\0-\\u00f0\\\\s\\\\B]$)|(?=.)(?!\\\\S|^|(?=\\\\2))\\\\1{4096,4097}\", \"gyi\"), b, z, x, NaN, b, x, y, x, NaN, x, eval =  \"\" , \u3056, \u3056, c, d, z, d, x, x, x, b, e, \u3056 = /\\B+|(?:(?!(?=(?![^])+|(?!\\B))))/yim, d, window, x = /(?=\\S)/yim, x, NaN, b, eval, x =  /x/g , eval, b = \"\\u90BF\", \u3056, x, NaN, x, x, x, e, x, a, x, a, w, NaN, of, x, eval = b, x, window, d = window, x, x, eval, w, z = undefined, window, window, e =  \"\" , \u3056) { yield ((void options('strict'))) } )));\n");
/*fuzzSeed-248247344*/count=753; tryItOut("/*ADP-2*/Object.defineProperty(a1,  /x/ , { configurable: false, enumerable: (x % 6 != 2), get: f2, set: (function mcc_() { var clobid = 0; return function() { ++clobid; f1(/*ICCD*/clobid % 7 == 3);};})() });\ni1 = new Iterator(e0);\n");
/*fuzzSeed-248247344*/count=754; tryItOut("mathy2 = (function(x, y) { return ( + (mathy1(Math.fround(Math.sinh((Math.acosh(Math.fround(Math.fround(Math.fround((((x >>> 0) ? (x >>> 0) : (x >>> 0)) >>> 0))))) | 0))), (Math.acos(Math.imul(x, x)) | 0)) ? ( + ( + mathy1(( + ( + Math.pow(( + (Math.atan2(y, Math.fround(x)) | 0)), ( + (Math.pow(( + y), ( + y)) >>> 0))))), ( + (Math.atan2(mathy1(( + -0), (y + Math.cbrt(y))), Math.hypot(Math.fround(x), ( - (Math.min(y, 2**53-2) >>> 0)))) | 0))))) : ( + ((Math.atan2((mathy0(y, Math.sign(y)) | 0), ((Math.fround(y) <= Math.fround(Math.min((x >>> 0), ( ! y)))) | 0)) | 0) * ( + ( ~ 0/0)))))); }); testMathyFunction(mathy2, [1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0x080000001, 2**53, -(2**53+2), -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, Number.MIN_VALUE, 0x07fffffff, -0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 0.000000000000001, -1/0, -0x080000001, 0x0ffffffff, -(2**53-2), -0x0ffffffff, Number.MAX_VALUE, 2**53+2, 0, 2**53-2, -0x100000000, 0x100000001, 1, -0, 42, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=755; tryItOut("/*RXUB*/var r = o0.r1; var s = g1.s0; print(r.exec(s)); ");
/*fuzzSeed-248247344*/count=756; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.g0.a1, o2);");
/*fuzzSeed-248247344*/count=757; tryItOut("i1.send(f2);\nv2 = evaluate(\"m2.get(s0);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (4277), noScriptRval: (x % 5 == 0), sourceIsLazy: true, catchTermination: (x % 6 != 3) }));\n");
/*fuzzSeed-248247344*/count=758; tryItOut("var vuznuo, c, x =  \"\" , umrgpk, yalxnr, x, oowcbb, delete, window, nlajeq;print(x);function x(x = ([/*UUV2*/(\u3056.imul = \u3056.setDate)]))\"use asm\";   var abs = stdlib.Math.abs;\n  var atan = stdlib.Math.atan;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Int16ArrayView[1]) = ((i1));\n    }\n    d0 = (-((+abs(((((-262143.0)) / ((+atan((( ''  %= \nx)))))))))));\n    d0 = (+((((1.0) < (-4194305.0)) ? (+(0.0/0.0)) : ((d0) + (Infinity)))));\n    {\n      i1 = (((-0xbe468*((imul((window **  \"\" ), (0x1b5ff5b3))|0) != ((x = timeout(1800)) & ((x)))))>>>(-0x27303*(11))) >= ((((((Uint32ArrayView[0]))>>>((0xfc1314ca)+(0xfa9b586c)+(0x5ed48489))) < (0x8f52c90c)))>>>((Int8ArrayView[4096]))));\n    }\n    {\n      d0 = (65537.0);\n    }\n    i1 = (0xce81fe60);\n    i1 = (i1);\n    return (((imul(((+(0x50cfbde)) >= (((-34359738369.0)) % ((295147905179352830000.0)))), (((((imul((1), ((0xf9958513)))|0)))|0)))|0) % (((i1)+(i1)+((Uint8ArrayView[4096]))) & (((0xffffffff) ? ((((0xc0d850f5)) ^ ((0x767f365d)))) : (-0x8000000))+(!(1))))))|0;\n  }\n  return f;print(x);h0.iterate = f0;");
/*fuzzSeed-248247344*/count=759; tryItOut("\"use strict\"; a0.shift();");
/*fuzzSeed-248247344*/count=760; tryItOut("mathy0 = (function(x, y) { return (Math.hypot((Math.fround(Math.hypot(((((Math.fround(( ! ( + Math.tanh(x)))) >>> 0) || (y >>> 0)) | 0) >>> 0), (Math.max(x, ( + ( + Math.asinh(( + y))))) >>> 0))) | 0), (((( + (( + (( + ( + (( - y) >> ( + (Math.atan(y) | 0))))) | 0)) | 0)) <= (( + ((x | 0) && (( + Math.atan2(Math.fround(( ! y)), ( + ( + (((((x >>> 0) << x) | 0) << x) | 0))))) | 0))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [-1/0, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), -Number.MAX_VALUE, -0, 42, 2**53+2, Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, 0x100000000, 2**53, 1, 0, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 0x07fffffff, -0x080000001, -0x100000000, 0x0ffffffff, -0x0ffffffff, -Number.MIN_VALUE, -(2**53), -(2**53+2), 0/0, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=761; tryItOut("(yield w = \u0009 \"\" ).__defineGetter__(\"x\", new Function);");
/*fuzzSeed-248247344*/count=762; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.log2(((Math.imul(Math.fround(( + Math.fround(Math.imul((Math.imul((y >>> 0), x) >>> 0), ( ! x))))), (( ~ (x > ( + mathy3((y >>> (y >>> 0)), (x ^ (y | 0)))))) >>> 0)) << mathy2(( ! Math.atan2(( + ( + 42)), x)), ( + ( + Math.max(y, 1))))) | 0)) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[-Infinity, arguments.callee, -Infinity, x, x, -Infinity, arguments.callee, arguments.callee, -Infinity, -Infinity, x, arguments.callee, x, -Infinity, arguments.callee, arguments.callee, -Infinity, -Infinity, x, arguments.callee, x, x, arguments.callee, arguments.callee, arguments.callee, x, arguments.callee, x, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, x, x, arguments.callee, arguments.callee, x, -Infinity, arguments.callee, -Infinity, x, arguments.callee, arguments.callee, -Infinity, x, x, arguments.callee, -Infinity, arguments.callee, x, -Infinity, arguments.callee, arguments.callee, -Infinity, arguments.callee]); ");
/*fuzzSeed-248247344*/count=763; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.exp(((Math.fround(x) ^ Math.fround(-0)) | -Number.MAX_VALUE)) % Math.fround(Math.fround(( + Math.min((y | 0), (( + (Math.min(y, (Math.sign(x) >>> 0)) >>> 0)) | 0)))))); }); testMathyFunction(mathy2, [-(2**53+2), 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), Math.PI, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -0x100000001, 1.7976931348623157e308, -0x100000000, -0x07fffffff, 0x07fffffff, 0x0ffffffff, -0x080000001, 1, -0x0ffffffff, 2**53+2, 42, -0, -0x080000000, -(2**53-2), 0x100000001, 0]); ");
/*fuzzSeed-248247344*/count=764; tryItOut("let(b = (function(q) { \"use strict\"; return q; }()), e, a = \"\\uACF3\", neyksf, y = x, window = x, c = \"\\uEE9D\", zfnmwb) { try { throw x; } finally { for(let z in  /* Comment */null) this.zzz.zzz; } }try { x.lineNumber; } catch(c) { return; } finally { for(let b in []); } ");
/*fuzzSeed-248247344*/count=765; tryItOut("\"use asm\"; Object.defineProperty(this, \"b0\", { configurable: (x % 5 == 4), enumerable: (4277),  get: function() {  return new SharedArrayBuffer(24); } });");
/*fuzzSeed-248247344*/count=766; tryItOut("e0.toSource = (function() { try { t0[18] = x; } catch(e0) { } try { b1 = t2.buffer; } catch(e1) { } try { /*MXX1*/o1 = o2.g0.Error.prototype.message; } catch(e2) { } for (var v of g2.s1) { try { v2 = t2.byteOffset; } catch(e0) { } try { /*ODP-1*/Object.defineProperty(b1, \"prototype\", ({enumerable: eval(\"/* no regression tests found */\")})); } catch(e1) { } try { e0.has(m0); } catch(e2) { } t0[18] = o2; } return a1; });");
/*fuzzSeed-248247344*/count=767; tryItOut("\"use strict\"; m1 + '';");
/*fuzzSeed-248247344*/count=768; tryItOut("NaN = d;");
/*fuzzSeed-248247344*/count=769; tryItOut("f0(t1);");
/*fuzzSeed-248247344*/count=770; tryItOut("const x;(false);");
/*fuzzSeed-248247344*/count=771; tryItOut("/*MXX1*/o1 = g2.Array.prototype.forEach;");
/*fuzzSeed-248247344*/count=772; tryItOut("\"use strict\"; { void 0; void schedulegc(this); }");
/*fuzzSeed-248247344*/count=773; tryItOut("\"use strict\"; \"use asm\"; if((4277)--) { if ((-4.eval(\"16\"))) {return;/*\n*/yield 14; }} else print(\"\\uC24E\");");
/*fuzzSeed-248247344*/count=774; tryItOut("var nuvdmx = new SharedArrayBuffer(6); var nuvdmx_0 = new Int32Array(nuvdmx); nuvdmx_0[0] = 16; var nuvdmx_1 = new Float64Array(nuvdmx); var nuvdmx_2 = new Uint32Array(nuvdmx); var nuvdmx_3 = new Uint16Array(nuvdmx); print(nuvdmx_3[0]); ;");
/*fuzzSeed-248247344*/count=775; tryItOut("mathy4 = (function(x, y) { return (Math.fround(( + Math.fround(( + Math.pow(( + (Math.sign(-0x0ffffffff) >>> 0)), Math.fround(Math.acos(y))))))) << ( - ( + (Math.log1p(x) >>> 0)))); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(false), new Boolean(false), (0/0), Infinity, new Boolean(false), (0/0), (0/0), (0/0), function(){}, new Boolean(false), Infinity, Infinity, new Boolean(false), Infinity, function(){}, (0/0), new Boolean(false), function(){}, (0/0), new Boolean(false), new Boolean(false), function(){}, new Boolean(false), new Boolean(false), new Boolean(false), (0/0), new Boolean(false), new Boolean(false), Infinity, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, new Boolean(false), (0/0), Infinity, function(){}, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, function(){}, new Boolean(false), function(){}, function(){}, (0/0), new Boolean(false), new Boolean(false), function(){}, Infinity, new Boolean(false), function(){}, function(){}, (0/0), (0/0), Infinity, new Boolean(false), Infinity, (0/0), (0/0), (0/0), function(){}, Infinity, new Boolean(false), Infinity, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, new Boolean(false), (0/0), new Boolean(false), Infinity, (0/0), Infinity, function(){}, Infinity, function(){}, Infinity, (0/0), (0/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (0/0), (0/0), function(){}, new Boolean(false)]); ");
/*fuzzSeed-248247344*/count=776; tryItOut("delete this.g1[\"repeat\"];");
/*fuzzSeed-248247344*/count=777; tryItOut("\"use strict\"; for(var z in ((Int32Array)((x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(x), (encodeURI).call, /*wrap3*/(function(){ \"use strict\"; var xdpdgt = (let (x =  '' ) x); ((/*wrap1*/(function(){ h0.delete = g2.f1;return Date.prototype.setTime})()).bind( /x/  != \"\\uB69B\", window))(); })))))){m2.delete(p2); }\u000c");
/*fuzzSeed-248247344*/count=778; tryItOut("mathy1 = (function(x, y) { return ( + (mathy0(((mathy0((Math.hypot((Math.round((Math.fround(Math.fround((Math.fround(y) | y))) ? (( + (y >>> 0)) >>> 0) : y)) >>> 0), (Math.hypot((Math.min(y, y) >>> 0), (Math.fround(mathy0(Math.fround(x), Math.fround(y))) >>> 0)) >>> 0)) >>> 0), (y >>> 0)) >>> 0) | 0), (Math.imul((Math.trunc(( + (-Number.MAX_VALUE ? x : -(2**53+2)))) >>> 0), (Math.fround(Math.fround(Math.expm1(2**53+2))) % Math.PI)) | 0)) | 0)); }); testMathyFunction(mathy1, [({toString:function(){return '0';}}), '0', (new Boolean(false)), '/0/', undefined, [0], 1, '\\0', NaN, (function(){return 0;}), true, (new Boolean(true)), (new Number(-0)), 0, false, -0, 0.1, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), [], /0/, ({valueOf:function(){return 0;}}), (new String('')), '', (new Number(0)), null]); ");
/*fuzzSeed-248247344*/count=779; tryItOut("\"use strict\"; let(d = Math.pow(new RegExp(\"(?:(?!^*)+|\\\\1(?=\\\\B)\\\\B|(?![^])*?*?)\", \"\"), -27), eval, vhzpjq, vvfkgj, y, rtpsqe, x = (x =  \"\" )) ((function(){for(let a of (4277) for (y of /*MARR*/[new String('q'), new String('q'), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]) for (x of  '' ) for (e of /*FARR*/[, true, ({caller: -24,  set __parent__(x, -6.b, e, x, a = 1247399524, c, b, NaN, e, w = \"\\u1174\", true = eval, x, x, x, x, x, e, x, x = a, x, NaN, y, x =  \"\" , b, x, y, x, y, a, eval, b, c, e, z, x, x, e, d, x, w, of, x, x, c = \"\\uC7F7\", \u3056, x, x, x = \"\\u4357\", window, e = 9, x, 1, x, y) { \"use strict\"; yield delete x.y }  }), x = Proxy.createFunction(({/*TOODEEP*/})(-10), (new Function(\"a2.sort(f2);\")), (1 for (x in [])))((void options('strict')), y), .../*MARR*/[new Number(1), new Number(1), new Number(1),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1), new Number(1), new Number(1),  /x/g ,  /x/g , new Number(1),  /x/g , new Number(1),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1),  /x/g , new Number(1),  /x/g ], Math.pow(((function too_much_recursion(mbwkij) { ; if (mbwkij > 0) { ; too_much_recursion(mbwkij - 1); {} } else {  }  })(1)), 3), .../*MARR*/[null, true, x >= b, new Number(1), x >= b, new Number(1), x, null, true, x >= b, true, x >= b, new Number(1), x >= b, x >= b, new Number(1), new Number(1), new Number(1), null, new Number(1), new Number(1), null, x >= b, null, x >= b, true, true, new Number(1), x, new Number(1), true, x, new Number(1), new Number(1), x, x >= b, x >= b, new Number(1), true, new Number(1), new Number(1), null, new Number(1), x >= b, true, null, x >= b, true, x, null, null, true, x, new Number(1), x >= b, null, new Number(1), x >= b, null, x, x, null, new Number(1), new Number(1), null, x >= b, x, x >= b, true, null, new Number(1), x, true, new Number(1), null, x]]) for each (d in /*FARR*/[, .../*FARR*/[, ...[x if (\"\\u707D\")], ++w, (x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(this), new RegExp(\".{1,}|[^]|[\\\\S\\u87ab-0]|[^]\\\\B^\\\\B*^\", \"g\"))), (4277).throw((this.zzz.zzz)), ((makeFinalizeObserver('tenured'))), .../*FARR*/[true, .../*PTHR*/(function() { for (var i of (function() { yield \"\\u0F46\"; } })()) { yield i; } })(), let (e = new RegExp(\"\\\\u9c7d|\\\\2\", \"gyi\")) window], ], [] = x, x, let (z = window)  '' , /./]) for each (x in new Array(14))) throw \u3056;})());");
/*fuzzSeed-248247344*/count=780; tryItOut("t1.set(t2, 13);");
/*fuzzSeed-248247344*/count=781; tryItOut("\"use strict\"; let crqlcv, c = \u3056, zydand;g0.f1(s1);");
/*fuzzSeed-248247344*/count=782; tryItOut("\"use strict\"; v1 = evalcx(\"x\", g1);");
/*fuzzSeed-248247344*/count=783; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let w of /*MARR*/[Number.MAX_VALUE, new Boolean(false), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), eval, Number.MAX_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), eval, eval,  'A' , new Boolean(false),  'A' , new Boolean(false), objectEmulatingUndefined(), Number.MAX_VALUE,  'A' , Number.MAX_VALUE, eval, objectEmulatingUndefined(), eval, objectEmulatingUndefined(), eval, eval, Number.MAX_VALUE,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , Number.MAX_VALUE, new Boolean(false), new Boolean(false), eval, new Boolean(false), new Boolean(false),  'A' , eval, eval, new Boolean(false), Number.MAX_VALUE, new Boolean(false), eval, Number.MAX_VALUE,  'A' ,  'A' , objectEmulatingUndefined(), Number.MAX_VALUE, new Boolean(false), eval, eval, objectEmulatingUndefined(),  'A' , eval, Number.MAX_VALUE, Number.MAX_VALUE, objectEmulatingUndefined(), eval, eval, eval,  'A' ,  'A' , objectEmulatingUndefined(), new Boolean(false), eval, objectEmulatingUndefined()]) { print(new RegExp(\"(?!.)+\", \"gm\")); }");
/*fuzzSeed-248247344*/count=784; tryItOut("/*RXUB*/var r = /(?=(?!^)|(?=(?=.))(?![\\w\\cL-\u46df\\v])+|[^]{2,33}|(?=.{2,}|\\u7223{16,}|[^]))+?(?=.){274877906944}|\\1|(?=.)|(?=(?!(?:\\W|[^]))[^])/m; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-248247344*/count=785; tryItOut("v2 = (o2.v2 instanceof b1);");
/*fuzzSeed-248247344*/count=786; tryItOut("let a, x = null |= -3, c = x.__defineGetter__(\"x\", Function), mpfwez, window = /*UUV2*/(w.splice = w.toLocaleUpperCase), xkatke, eebhev;/*RXUB*/var r = new RegExp(\"(?!.)\", \"i\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); \nb1 = t1.buffer;\n");
/*fuzzSeed-248247344*/count=787; tryItOut("h1 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.push.call(a2, o0.o1, g0.g0);; var desc = Object.getOwnPropertyDescriptor(v2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { t0[19] = (([] = x <  \"\" ));; var desc = Object.getPropertyDescriptor(v2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Array.prototype.sort.apply(a2, [f1]);; Object.defineProperty(v2, name, desc); }, getOwnPropertyNames: function() { /*RXUB*/var r = this.o2.r0; var s = \"\"; print(s.replace(r, (4277))); ; return Object.getOwnPropertyNames(v2); }, delete: function(name) { v1 = (p2 instanceof m0);; return delete v2[name]; }, fix: function() { Object.prototype.watch.call(g1.v2, -8, (function() { try { i1.next(); } catch(e0) { } v1 = (i0 instanceof a1); return o0; }));; if (Object.isFrozen(v2)) { return Object.getOwnProperties(v2); } }, has: function(name) { a2[12];; return name in v2; }, hasOwn: function(name) { return m2; return Object.prototype.hasOwnProperty.call(v2, name); }, get: function(receiver, name) { a1.pop(g1, t0);; return v2[name]; }, set: function(receiver, name, val) { Object.preventExtensions(this.e1);; v2[name] = val; return true; }, iterate: function() { /*ODP-1*/Object.defineProperty(s1, \"asinh\", ({get: (4277), set: (Array.isArray).bind}));; return (function() { for (var name in v2) { yield name; } })(); }, enumerate: function() { a2[({valueOf: function() { v1 = 4.2;return 16; }})] = ( + x);; var result = []; for (var name in v2) { result.push(name); }; return result; }, keys: function() { g2.o0.g2.v1 = t1.length;; return Object.keys(v2); } });");
/*fuzzSeed-248247344*/count=788; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((( ! Math.fround(Math.min(0x100000000, ( + (y % x))))) | 0) << (( + Math.expm1((mathy0(Math.atan(x), (Math.hypot(((( + (y ^ x)) ? ( + (Math.cbrt(Math.fround(Math.atan2(Math.fround(2**53), (y >>> 0)))) | 0)) : ( + 0x100000000)) >>> 0), Math.asin(( + ( ~ ( + x))))) | 0)) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=789; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(Math.fround(Math.fround(( ! Math.fround((-(2**53+2) ** Math.expm1((y >>> 0))))))), (Math.round(( + Math.atan(y))) >>> 0)); }); testMathyFunction(mathy2, [Math.PI, 0/0, -0x080000000, 42, Number.MIN_SAFE_INTEGER, -0x100000001, 0, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 1, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, -(2**53), 0x07fffffff, -(2**53-2), 2**53, -0x100000000, 1/0, -0x080000001, -1/0, 0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001]); ");
/*fuzzSeed-248247344*/count=790; tryItOut("switch(-/\\t/gi) { default: case 4: break;  }");
/*fuzzSeed-248247344*/count=791; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + ( ! Math.fround(( + Math.tan(( + (((Math.fround(Math.log1p(Math.fround(42))) | 0) >>> ( + ( ~ (y >>> 0)))) | 0))))))) || (Math.fround(( + ( + (( + ( ~ ( + ( + x)))) + Math.acosh(((y >>> 0) ? (x >>> 0) : (x >>> 0))))))) || (( - Math.sin(Math.max(Math.min(y, (y | 0)), x))) >>> 0))); }); testMathyFunction(mathy4, [0.000000000000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, -0, -1/0, Number.MAX_VALUE, -0x080000000, -0x0ffffffff, -0x080000001, 0, 2**53, Math.PI, 42, 1/0, -0x100000001, 2**53-2, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, -0x07fffffff, 0x080000001, 0x080000000, -Number.MAX_VALUE, 1, -Number.MIN_VALUE, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-248247344*/count=792; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-16777217.0));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-1/0, 1.7976931348623157e308, Math.PI, 0/0, 2**53+2, -(2**53), -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, -(2**53+2), 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0x080000001, -0x100000001, 0x100000001, 2**53-2, -0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 0x07fffffff, -0x0ffffffff, 0x080000000, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-248247344*/count=793; tryItOut("mathy0 = (function(x, y) { return Math.hypot(Math.log((((Math.max(y, -(2**53-2)) >>> 0) ** (Math.min((( + (Math.atan2(0x0ffffffff, x) | 0)) | 0), ( - (x >> Math.fround(-0x080000000)))) >>> 0)) >>> 0)), Math.atan2(Math.atanh(((( + y) !== x) != (-0x100000001 | 0))), (( ~ (((0 >>> 0) != ((Math.fround(x) ? Math.fround(-(2**53)) : Math.fround((Number.MAX_VALUE ? x : y))) >>> 0)) >>> 0)) % ( + y)))); }); testMathyFunction(mathy0, [1/0, 42, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), -Number.MIN_VALUE, Math.PI, -0x0ffffffff, 0/0, 0x0ffffffff, 0, Number.MAX_VALUE, 2**53, 0x100000001, 0x100000000, 2**53+2, 1, 0x07fffffff, 1.7976931348623157e308, -1/0, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, -0x080000000, -(2**53-2), -Number.MAX_VALUE, -0x07fffffff, 0x080000000, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=794; tryItOut("\"use strict\"; /*infloop*/do {print(((function sum_indexing(zaheyj, jxbbey) { p0.valueOf = (function(j) { f1(j); });; return zaheyj.length == jxbbey ? 0 : zaheyj[jxbbey] + sum_indexing(zaheyj, jxbbey + 1); })(/*MARR*/[new Number(1.5), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1.5), new String(''), new Boolean(true), (0/0)], 0))); } while(x);");
/*fuzzSeed-248247344*/count=795; tryItOut("print((4277));function x(x)\"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (1);\n    i1 = (i1);\n    (Int32ArrayView[4096]) = ((0xffffffff) / ((((((i0)) << ((i0)+(i1))) <= (0x929235e)))>>>(-0xfffff*(i0))));\n    {\n      {\n        (Float32ArrayView[((i0)+(i0)) >> 2]) = ((Float64ArrayView[0]));\n      }\n    }\n    return (((((((295147905179352830000.0) < (((1.1805916207174113e+21)) % ((-3.022314549036573e+23))))+(i0)) | ((1))) > (0x3ac71c0d))-(i1)))|0;\n  }\n  return f;(/Array.prototype.sort.apply(a2, [(function mcc_() { var mxuajb = 0; return function() { ++mxuajb; f1(/*ICCD*/mxuajb % 3 == 2);};})()]);");
/*fuzzSeed-248247344*/count=796; tryItOut("\"use strict\"; a0[Math.pow(((yield null)), 5).__defineGetter__(\"NaN\", (4277))] = m1;");
/*fuzzSeed-248247344*/count=797; tryItOut("v0 = Object.prototype.isPrototypeOf.call(g2.f1, f0);");
/*fuzzSeed-248247344*/count=798; tryItOut("mathy4 = (function(x, y) { return ((Math.hypot(Math.fround(mathy1(Math.max(Math.tan(y), ((Math.fround(( - Math.fround(x))) ? y : ( + ( ~ ( + -(2**53-2))))) >>> 0)), (( + Math.PI) != ( + y)))), Math.fround((Math.max(Math.log(Math.asin(y)), (( + x) | 0)) | 0))) >>> 0) ^ ( - ( + mathy2(( + x), ( + ( + Math.imul(Math.fround(0.000000000000001), x))))))); }); testMathyFunction(mathy4, [NaN, '/0/', ({valueOf:function(){return 0;}}), [0], '', '\\0', null, undefined, [], (new Number(-0)), 1, ({toString:function(){return '0';}}), (new Number(0)), (function(){return 0;}), '0', -0, (new Boolean(true)), 0, (new String('')), objectEmulatingUndefined(), 0.1, false, true, /0/, ({valueOf:function(){return '0';}}), (new Boolean(false))]); ");
/*fuzzSeed-248247344*/count=799; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=800; tryItOut("a0.unshift(g1);");
/*fuzzSeed-248247344*/count=801; tryItOut("print(x);function z(z)'fafafa'.replace(/a/g, true)g0.v1 = a2.length;\nwith(x.setInt32())v1 = t0.length;\n");
/*fuzzSeed-248247344*/count=802; tryItOut(" for (var x of window) v0 = evalcx(\"/*MXX2*/g1.RegExp = a2;\", g1);");
/*fuzzSeed-248247344*/count=803; tryItOut("mathy5 = (function(x, y) { return mathy4(( + ( + Math.sqrt(Math.abs(y)))), (( + ( + ((( + (y % Math.fround(1))) | 0) >>> 0))) >>> 0)); }); testMathyFunction(mathy5, [-(2**53-2), 2**53-2, Number.MAX_VALUE, 1, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, 42, -(2**53), 0.000000000000001, 0x07fffffff, 0, 0x080000001, 0x100000000, 2**53+2, -(2**53+2), 0x080000000, -Number.MIN_VALUE, Math.PI, -0x100000000, -0x080000001, 0x100000001, -Number.MAX_VALUE, 0/0, 2**53, -0x100000001, -0, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=804; tryItOut("/*bLoop*/for (let cionyu = 0; cionyu < 68; ++cionyu) { if (cionyu % 20 == 9) { /*oLoop*/for (let itdhnn = 0, x; itdhnn < 14; ++itdhnn) { t1.set(a2, 16); }  } else { print(x); }  } ");
/*fuzzSeed-248247344*/count=805; tryItOut("testMathyFunction(mathy4, [Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, Math.PI, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x07fffffff, 0x100000000, 0x080000000, 0, 0x100000001, 0x080000001, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, -0, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 42, -0x100000000, 1, -1/0, 0.000000000000001, 2**53+2]); ");
/*fuzzSeed-248247344*/count=806; tryItOut("m2 = new Map(p1);");
/*fuzzSeed-248247344*/count=807; tryItOut("switch((c += y)) { default: break; case 6: break; /*RXUB*/var r = new RegExp(\"(?=(?=\\\\2)\\\\W{4}?)\", \"ym\"); var s = \"00}000a00000\"; print(r.test(s)); case 9: break; case 4: a1.shift(\"\\u3C68\", m2, o0.i1);\nprint(x);\nbreak; this.g2.v1 = Object.prototype.isPrototypeOf.call(b0, o0.v2);break;  }");
/*fuzzSeed-248247344*/count=808; tryItOut("v0 = evalcx(\"i0.next();\", g0);");
/*fuzzSeed-248247344*/count=809; tryItOut("mathy1 = (function(x, y) { return (( + mathy0(( + ( + (Math.fround(Math.imul(Math.min(( + ( + (y ? y : x))), 0x07fffffff), y)) ** ( ~ Math.min((Math.imul((mathy0(x, y) | 0), (y | 0)) | 0), (y >>> 0)))))), ( + ((( ! 1) >= (Math.atanh((0x080000000 | 0)) | 0)) ^ Math.fround(Math.sin(( + ( ~ ( + y))))))))) & Math.acos((Math.fround((( ~ Math.max(x, Math.atan2((-0x07fffffff >>> 0), ( + -0)))) !== ( + ( ~ ( + Math.fround(( - Math.fround(Math.imul(x, 1.7976931348623157e308))))))))) > x))); }); ");
/*fuzzSeed-248247344*/count=810; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=811; tryItOut("Array.prototype.shift.call(g2.a2);");
/*fuzzSeed-248247344*/count=812; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ~ ( + mathy0(( + ( + mathy0(( + Math.log1p(( ! x))), (Math.fround((((y >>> 0) / Math.pow((y << y), y)) >>> 0)) * x)))), ( + ( + (( + ( + Math.clz32(( + Math.atan2((mathy1((y >>> 0), (mathy2(y, y) >>> 0)) >>> 0), ( + Math.pow(Math.expm1(1/0), -(2**53)))))))) >> (( - ( + ( ! y))) | 0))))))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 1, 0, 2**53-2, -0, -0x100000001, -(2**53+2), 0x0ffffffff, -(2**53-2), Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 0x100000001, 0.000000000000001, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 2**53, 1.7976931348623157e308, 0x080000001, 0/0, 0x07fffffff, -0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, -0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=813; tryItOut("L:for(c = /*UUV1*/(x.fontcolor = /*wrap1*/(function(){ \"use strict\"; \"use asm\"; for (var v of f0) { try { v2 = Array.prototype.reduce, reduceRight.call(o1.a1, new RegExp(\"\\\\1\", \"yi\")); } catch(e0) { } /*ADP-3*/Object.defineProperty(a1, ({valueOf: function() { (\"\\u4373\");return 12; }}), { configurable: true, enumerable: false, writable:  '' , value: i0 }); }return -15})()) in new RegExp(\"(?=\\\\W*\\\\B)|(?!(( )))+?{4,4}\", \"gyim\")) {{t2[9] = e1;yield; }var d;Array.prototype.push.apply(g0.a1, [m2, b2]); }");
/*fuzzSeed-248247344*/count=814; tryItOut("\"use strict\"; /*infloop*/for(let y = \u3056 << \u3056; x; [1,,]) {e2.toString = null; }");
/*fuzzSeed-248247344*/count=815; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (((( + Math.pow(y, (y == Math.fround(y)))) != (( + 0/0) & ( + ( ! ( + Math.tanh(y)))))) >>> 0) != Math.hypot(( ~ (( - (mathy2((x | 0), (x | 0)) >>> 0)) >>> 0)), y))); }); ");
/*fuzzSeed-248247344*/count=816; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    (Float32ArrayView[1]) = ((-1125899906842624.0));\n    {\n      d1 = (1025.0);\n    }\n    return (((0x392ac220)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"e1 = Proxy.create(h2, h0);\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Math.PI, -(2**53), -0x080000000, -0x0ffffffff, 0x100000001, 1, -(2**53-2), 0.000000000000001, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 1/0, -(2**53+2), -0, -1/0, 0x080000000, 0, 2**53+2, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, 42, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-248247344*/count=817; tryItOut("delete g2[ /x/ ];");
/*fuzzSeed-248247344*/count=818; tryItOut("\"use strict\"; v1 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=819; tryItOut("\"use strict\"; /*MXX1*/o2 = o2.g0.WeakSet.prototype;");
/*fuzzSeed-248247344*/count=820; tryItOut("/*MXX3*/g0.String.prototype.search = g0.String.prototype.search;");
/*fuzzSeed-248247344*/count=821; tryItOut("m1.has(i0);");
/*fuzzSeed-248247344*/count=822; tryItOut("if(false) {throw new RegExp(\"(?=.)^|(?:$){2}((?:^)){1,}|(?=(?!\\\\b)|(?:(?=\\\\b\\\\b)))\", \"ym\");i0 = m0.entries; } else  if (x) o0.t2 + '';");
/*fuzzSeed-248247344*/count=823; tryItOut("/*bLoop*/for (hxpktu = 0; hxpktu < 92; ++hxpktu) { if (hxpktu % 5 == 2) { /*MXX1*/o2 = this.g2.Int32Array.prototype.constructor; } else { m1.has(t2); }  } ");
/*fuzzSeed-248247344*/count=824; tryItOut("v2 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=825; tryItOut("\"use strict\"; v0 = (v0 instanceof o2);");
/*fuzzSeed-248247344*/count=826; tryItOut("\"use strict\"; a2.push(e2);");
/*fuzzSeed-248247344*/count=827; tryItOut("g1 + '';");
/*fuzzSeed-248247344*/count=828; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=829; tryItOut("t0 = new Uint16Array(a2);");
/*fuzzSeed-248247344*/count=830; tryItOut("\"use strict\"; \"use asm\"; {x = (RegExp.prototype.toString)(), a, eedamn, x, eval;v1 + o0; }");
/*fuzzSeed-248247344*/count=831; tryItOut("x = (4277), y = --NaN, x, z = /*FARR*/[(4277)].filter(((void options('strict'))), x), y =  | Math.hypot(/(?!^[\\d\\b-\\u3097]+?.{3,})?(?=(?=(\\b))*?.{2,3}\\S)/gyim, x), d = (x >>= ((Object.prototype.__lookupSetter__).call([[1]], )));/*hhh*/function \u0009aojpca(a = Function.prototype, x = new (a =>  { \"use strict\"; yield this } )([1,,],  \"\" ) ^= (eval(\"m1 = new WeakMap;\", 15)), x, x = eval !== b, x, d, \u3056, eval = window, eval, a, b, c, x, x, d, x, a, this, window, z, x, eval, x, x, x = -10, window, eval, x = -13, x, x, eval, \u3056, a, window =  '' , \u3056 = \"\\u8CAC\", x, x, window, window, \u3056, NaN, eval, x = new RegExp(\"((?=[^]|$*|(?![^])((\\\\b))\\\\B))\", \"y\"), z, w, x = undefined, x, x, NaN, c, x, x, a, window, let, eval, b, x, y, x, y, x = new RegExp(\"(?!^|(?:\\u008d\\\\B)[^]|\\\\b?+)|(?:(?!(?!(?:\\\\uF438)){3,})){4}\", \"yi\"), b, x = -7, z =  /x/ , c =  '' , this.x, x, x){this.a0 = new Array;}/*iii*/;");
/*fuzzSeed-248247344*/count=832; tryItOut("i2.next();");
/*fuzzSeed-248247344*/count=833; tryItOut("this.e1.has(this.g1.o1);");
/*fuzzSeed-248247344*/count=834; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy0, [2**53-2, 2**53, 0x100000001, Number.MIN_SAFE_INTEGER, 1/0, 0/0, -(2**53-2), 1.7976931348623157e308, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -0x100000001, 0x100000000, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, -Number.MIN_VALUE, 42, 1, -1/0, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, -0x100000000, 0x080000001, Math.PI, -Number.MAX_VALUE, Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-248247344*/count=835; tryItOut("g0.v1 = Object.prototype.isPrototypeOf.call(i2, v1);");
/*fuzzSeed-248247344*/count=836; tryItOut("/*infloop*/for(let x in (((function(x, y) { return (( - ((((Math.fround(Math.imul((((( ~ Math.fround((Math.fround(Math.hypot(Math.pow((( ~ 0) >>> 0), Math.fround(Math.atan2(Math.clz32(Math.imul(-Number.MAX_SAFE_INTEGER, x)), Math.fround((0x100000001 >= ( + 2**53)))))), ( + Math.atan((Math.trunc(x) >>> 0))))) * Math.fround(((((x ? x : x) | 0) ? (Math.log2(Math.max(-0x100000001, ( + x))) | 0) : 2**53) | 0))))) | 0) != ((( - (( ~ Math.fround((Math.acosh(Math.fround(Math.log2(( + x)))) | 0))) | 0)) | 0) | 0)) | 0), Math.fround(( ! Math.atan2(( + ( + ( + ( ~ x)))), h0.get = Array.prototype.slice.bind(m2);))))) & Math.fround((Math.fround(((Math.fround(Math.cbrt(Math.fround(Math.min((( + (Math.imul(( + ( + y)), -0x100000001) | 0)) | 0), Math.hypot(( + ((((Math.log2((Math.fround((Math.fround(x) >= Math.fround(y))) | 0)) | 0) | 0) !== Number.MIN_SAFE_INTEGER) | 0)), ( + x)))))) | 0) <= Math.fround(( ! Math.fround((Math.pow(Math.fround(Math.fround((Math.fround(x) ? Math.fround(Math.fround((Math.fround(( + ((x >>> 0) == (x >>> 0)))) < Math.fround(-0x100000000)))) : Math.imul(x, Math.round((x ** x)))))), (Math.fround(( + Math.imul(Math.fround(Math.hypot(42, ( + Math.atanh((x | 0))))), ( + 0/0)))) >>> 0)) >>> 0)))))) ? Math.fround(Math.fround(( ~ Math.cos(Math.acosh(Math.fround(Math.asin(x))))))) : (( + (Math.fround(((( + ( ! Math.fround(( + ( + (( + ((0x080000001 ? Math.fround(y) : ((y & (Math.atanh(x) >>> 0)) >>> 0)) >>> 0)) < ( + Math.hypot(-0x0ffffffff, x)))))))) >>> 0) & ((( ! ( + ((( + ( + Math.ceil(x))) === Math.hypot(x, (Math.sinh((x >>> 0)) >>> 0))) | 0))) >>> 0) >>> 0))) && (Math.atan2(Math.fround(( - Math.max(-0x080000000, ( ~ ( + (( + 0x080000001) ? ( + x) : ( + x))))))), Math.log2(Math.fround(( - y)))) >>> 0))) >>> 0)))) >>> 0) * (( - Math.fround(( ~ Math.fround(( + Math.fround(Math.imul((Math.sqrt(( + (Math.fround(( + Math.asinh(( + y)))) ? ( + y) : Math.fround(x)))) ? (( + (x >>> 0)) | 0) : Math.sinh(( + Math.atan(( + ( ~ ( + ( + Math.min(( + 2**53), ( + x)))))))))), (Math.tanh(( ! y)) >>> 0)))))))) >>> 0)) >>> 0)) & Math.fround(( ~ Math.imul(Math.fround((( + (( - (((((((Math.asin((( + Math.min((( ! ( + (Math.atan2(x, y) >>> 0))) | 0), x)) >>> 0)) <= Math.imul(Math.min((Math.fround((Math.fround(Math.pow((x | 0), y)) << Math.fround((Math.pow(0, x) < x)))) >>> 0), (x >>> 0)), y)) << (Math.max(Math.sin(y), ( + Math.pow(Math.fround(0.000000000000001), x))) >>> 0)) >>> 0) | 0) >>> ((( - Math.imul((( + x) , ( + Math.exp(Math.atan(( + Math.fround((Math.fround(x) > 0.000000000000001))))))), (( + ((( - x) ? (y | 0) : y) >>> 0)) !== ( + (( - y) ** x))))) | 0) | 0)) | 0) | 0)) >>> 0)) >>> 0)), Math.fround((Math.sinh((Math.imul((Math.atanh((( + ( + Math.min(( + (((x >>> 0) !== (Math.tanh((((x >>> 0) == y) >>> 0)) >>> 0)) >>> 0)), ( + Math.atanh((((( + x) | 0) ** Math.asin((x | 0))) | 0)))))) | 0)) | 0), Math.trunc(Math.log10(Math.atan2(( + (( ! (x | 0)) == (y >>> 0))), ( + ((y >>> 0) ? (Math.fround((x ? Math.imul(y, -0x07fffffff) : Math.sqrt(y))) | 0) : Math.fround(Math.hypot(-0x080000001, (Math.imul(Math.fround(-0x07fffffff), (Math.fround(( - (y | 0))) >>> 0)) >>> 0))))))))) | 0)) | 0)))))); }))(((p={}, (p.z = x)()))))){t0[5] = this.__defineSetter__(\"x\", delete NaN.x).valueOf(\"number\");print(new RegExp(\".\\\\B|\\\\x69|\\\\u005C.[\\\\S\\\\u35A7-\\\\uD104]*?{2,268435459}|([^\\\\x492-\\ufb82]*?)+\", \"\"));function eval() { \"use strict\"; return new RegExp(\"(?!(?=\\\\S)+?)\", \"yi\") } Array.prototype.forEach.apply(a2, [(function() { try { this.e2.add(x); } catch(e0) { } try { t2.set(a1, v0); } catch(e1) { } print(uneval(a2)); return a0; })]); }");
/*fuzzSeed-248247344*/count=837; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((((((( - Math.fround(x)) | 0) ? ((((( + Math.log1p(( + 1.7976931348623157e308))) > (Math.hypot(( + ( + y)), 0x100000000) | 0)) ? (Math.hypot(Number.MAX_VALUE, y) | 0) : (( ~ Number.MAX_VALUE) | 0)) | 0) >>> 0) : (((0.000000000000001 >>> 0) , (( + Math.cosh(y)) | 0)) >>> 0)) >>> 0) | 0) , (Math.min((mathy2(((( + x) / ( + ( ! y))) >>> 0), Math.fround(( + (0x100000000 == x)))) ? -0x080000001 : ( ! Math.fround((y != y)))), (( + mathy0((mathy1((2**53+2 | 0), (( + ( - y)) | 0)) | 0), (Math.tan(2**53-2) + x))) - Math.fround((( + 2**53-2) == Math.fround(Math.acos(x)))))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=838; tryItOut("\"use strict\"; e2.add(t2);");
/*fuzzSeed-248247344*/count=839; tryItOut("\u0009const lyeqov, [] = (w !== eval), ybxira, yxyroe, window, xqgraq, window = Math.max(-16, window), iofpgp, x;(Math.atanh(27).eval(\"t0 = new Uint8ClampedArray(t0);\"));");
/*fuzzSeed-248247344*/count=840; tryItOut("i1.send(o2);");
/*fuzzSeed-248247344*/count=841; tryItOut("\"use strict\"; {for (var p in t2) { try { s1 += s1; } catch(e0) { } try { v0 = (g1.b2 instanceof f0); } catch(e1) { } try { Array.prototype.push.apply(a2, [p1, g1.a2]); } catch(e2) { } a2.reverse(o2.t0, m2); } }");
/*fuzzSeed-248247344*/count=842; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (((Math.pow((Math.sinh(( + (Math.fround(x) >>> Math.fround(Math.min(Math.fround(( + ( ! ( + 42)))), (x | 0)))))) >>> 0), (Math.atan2(( + Math.min(((mathy0(x, y) | 0) | 0), ((Math.hypot((( + (Math.fround(( ! Math.fround(y))) || y)) >>> 0), (y >>> 0)) >>> 0) | 0))), Math.imul(Math.fround(y), x)) >>> 0)) >>> 0) | 0) % Math.imul(( + ( - ( + Math.log(( + x))))), Math.hypot((Math.ceil(x) < Math.tanh((x | 0))), Math.imul(Math.imul(x, Math.atanh(y)), mathy0((-0x080000000 >>> 0), x))))); }); ");
/*fuzzSeed-248247344*/count=843; tryItOut("\"use strict\"; /*infloop*/for(\u3056 in  \"\" ) h0.toString = Set.prototype.delete.bind(v0);\n/* no regression tests found */\n");
/*fuzzSeed-248247344*/count=844; tryItOut("Object.seal(e2);");
/*fuzzSeed-248247344*/count=845; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-248247344*/count=846; tryItOut("\"use strict\"; /*vLoop*/for (let xqcjmk = 0; xqcjmk < 37; ++xqcjmk) { const z = xqcjmk; /*MXX2*/g1.String.prototype.match = t0; } ");
/*fuzzSeed-248247344*/count=847; tryItOut("/*RXUB*/var r = /[\\s\\w -\\xe4\\d]/; var s = \" \"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=848; tryItOut("/*RXUB*/var r =  /x/ ; var s = \"1a\\uea14a\\naa\"; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=849; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.atanh(Math.fround((Math.hypot(( + Math.pow(( + mathy3(Math.asinh((Math.atanh((y | 0)) | 0)), Math.fround((mathy3(0x07fffffff, -0x080000000) ? x : (mathy2(( + x), ( + 2**53-2)) | 0))))), Math.ceil((Math.imul(y, Math.fround(Math.fround(( + ( + x))))) >>> 0)))), (Math.atan2(( ! mathy3(y, x)), x) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [-0x080000000, 1.7976931348623157e308, 0/0, 1, -(2**53), 2**53+2, -1/0, 0x0ffffffff, -0x07fffffff, -0x100000000, -0x080000001, -0x0ffffffff, 0x080000001, 0.000000000000001, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, 0, 42, -(2**53+2), -0, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 0x100000001, 2**53-2, Math.PI, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0x080000000]); ");
/*fuzzSeed-248247344*/count=850; tryItOut("Array.prototype.shift.call(o1.a2, g0.e0);");
/*fuzzSeed-248247344*/count=851; tryItOut("\"use strict\"; /*infloop*/for(var /*FARR*/[\"\\u288E\", , x].some ? null.yoyo(function(id) { return id }) -= this.__defineGetter__(\"x\", Object.getOwnPropertyDescriptor) : \u0009let (vnjahi)  /x/ .watch(\"16\", /*wrap2*/(function(){ var yzwolp = /\\B/y; var zbphxc = function shapeyConstructor(lgypso){this[\"constructor\"] = this;if (window) Object.defineProperty(this, \"valueOf\", ({configurable: false}));this[\"callee\"] =  /x/g ;Object.preventExtensions(this);if ( '' ) Object.defineProperty(this, \"constructor\", ({get: \"\\uA971\", set: window, configurable: false}));Object.defineProperty(this, \"constructor\", ({get: (function(x, y) { \"use strict\"; return lgypso; }), set: new Function}));this[\"callee\"] = new Boolean(false);Object.freeze(this);this[\"callee\"] = NaN;Object.defineProperty(this, \"valueOf\", ({configurable: true, enumerable: false}));return this; }; return zbphxc;})()) = arguments.callee.arguments = (window\n) ? window.eval(\"window\") : (-15.throw(x)) **= (4277); \"\\u5E1A\"; (a) = window) {selectforgc(o2);print(o1);v0 = Object.prototype.isPrototypeOf.call(o1.a1, e1); }");
/*fuzzSeed-248247344*/count=852; tryItOut("let (x) { /*MXX1*/o0 = g1.DataView.prototype.setUint8; }");
/*fuzzSeed-248247344*/count=853; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((Math.abs(x) !== ( - -Number.MIN_VALUE)) | 0) ? Math.max(((x % ( + Math.sign(( + Math.max((Math.fround(y) ? 0x080000000 : y), ( - (y ? Math.PI : x))))))) | 0), (Math.fround(( + Math.atan2(Math.fround((Math.abs(y) >>> 0)), Math.cbrt(y)))) | 0)) : (Math.fround(Math.min(0x080000001, (Math.exp(Math.fround((((Math.imul(Math.fround(y), (y | 0)) >>> 0) >>> 0) == x))) | 0))) | 0)); }); testMathyFunction(mathy0, [-(2**53-2), -Number.MAX_VALUE, -1/0, -(2**53+2), 0x080000000, 0, 42, -0x100000000, Math.PI, -0x100000001, 2**53, 1, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -(2**53), -0x0ffffffff, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -0, 0x0ffffffff, -0x07fffffff, 1/0, 0x100000000, 0x080000001, 0/0]); ");
/*fuzzSeed-248247344*/count=854; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul((((Math.pow(( - Math.fround(( + -Number.MIN_SAFE_INTEGER))), (y ? x : mathy0(Math.fround(Math.ceil(x)), x))) | 0) >= (mathy0(Math.fround(( ! Math.fround(Math.pow(Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround(y)))), Math.fround(Math.min(x, Math.clz32(x))))))), mathy0(x, (Math.atan2((x >>> 0), (x >>> 0)) >>> 0))) | 0)) | 0), ( ~ Math.acosh(Math.log2(-(2**53+2))))); }); testMathyFunction(mathy1, [42, -0x080000000, 0, 0/0, -(2**53+2), -(2**53-2), Number.MAX_VALUE, 1, Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -Number.MAX_VALUE, Math.PI, 0.000000000000001, -0, 2**53+2, 1/0, -0x100000000, 0x07fffffff, 2**53-2, -Number.MIN_VALUE, 0x100000001, -1/0, 1.7976931348623157e308, -0x07fffffff, -0x100000001, -0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 0x100000000]); ");
/*fuzzSeed-248247344*/count=855; tryItOut("\"use strict\"; /*hhh*/function aezpmz(x, eval){o2.m1 = new WeakMap;}aezpmz(( /x/g .valueOf(\"number\")) > let (aozpes) x);");
/*fuzzSeed-248247344*/count=856; tryItOut("\"use strict\"; (((function too_much_recursion(ctmxgx) { ; if (ctmxgx > 0) { ; too_much_recursion(ctmxgx - 1);  } else {  }  })(3)));");
/*fuzzSeed-248247344*/count=857; tryItOut("e2 = new Set;");
/*fuzzSeed-248247344*/count=858; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0x080000001, -0x100000000, 0x100000000, 1, 0.000000000000001, Number.MIN_VALUE, -0x080000001, -1/0, -(2**53-2), -0, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, 2**53, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, Number.MAX_VALUE, 0, -0x080000000, 2**53+2, -(2**53), -Number.MAX_VALUE, 0/0, -0x07fffffff, -(2**53+2), 0x100000001, 1/0]); ");
/*fuzzSeed-248247344*/count=859; tryItOut("\"use strict\"; for(let z in (([,,z1])(x)))m2 = t2[({valueOf: function() { o2.o2 = e1.__proto__;return 1; }})];");
/*fuzzSeed-248247344*/count=860; tryItOut("xssjsc(((makeFinalizeObserver('nursery')) ^= x));/*hhh*/function xssjsc(b){i2 = new Iterator(m0, true);}");
/*fuzzSeed-248247344*/count=861; tryItOut("/*MXX2*/g1.WebAssemblyMemoryMode = o0.g0.i1;");
/*fuzzSeed-248247344*/count=862; tryItOut("testMathyFunction(mathy1, [-0x080000001, -0x07fffffff, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -1/0, 1/0, 0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, -0x100000000, 0x100000000, -Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, Math.PI, 0, -0, -0x080000000, -0x0ffffffff, 2**53, 42, Number.MAX_VALUE, 0/0, 0x100000001, -0x100000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 1, 0x080000000]); ");
/*fuzzSeed-248247344*/count=863; tryItOut("i0.send(b0);");
/*fuzzSeed-248247344*/count=864; tryItOut("print(m1);");
/*fuzzSeed-248247344*/count=865; tryItOut("mathy3 = (function(x, y) { return ((( + (1 >>> 0)) / Math.fround(Math.atan2(Math.min(x, x), ((Math.hypot(((((y ? (Math.atan2((x | 0), Math.fround(y)) | 0) : -(2**53-2)) >>> 0) != Number.MAX_SAFE_INTEGER) | 0), Math.fround(( ~ ( + ( + ( + y)))))) | 0) | 0)))) ^ ( ~ (((Math.asin(( + Math.fround(( + -Number.MAX_SAFE_INTEGER)))) >>> 0) & (((( + Math.clz32((x | 0))) !== (((y | 0) % ( + -(2**53+2))) >>> 0)) | 0) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-248247344*/count=866; tryItOut("\"use strict\"; b = (yield x), x = (\u3056-- /= window.yoyo(true)), z;Array.prototype.splice.call(a1, -16, ({valueOf: function() { t1.set(g2.a1, x);return 2; }}));");
/*fuzzSeed-248247344*/count=867; tryItOut("\"use strict\"; a2[19] = s2;");
/*fuzzSeed-248247344*/count=868; tryItOut("\u000clet c, NaN = [,], x = [[1]];g2 + m2;");
/*fuzzSeed-248247344*/count=869; tryItOut("/*infloop*/M:for([] = (Math.pow(this, -0)); (4277); (x = x)) (void shapeOf(-11)) = a0[v0];");
/*fuzzSeed-248247344*/count=870; tryItOut("print(uneval(a1));");
/*fuzzSeed-248247344*/count=871; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ((mathy1(( ! y), x) >>> 0) != ( + ( + y)))) / ( + (Math.fround(Math.expm1(Math.min(( ~ ( + ((x | 0) % ( + y)))), ((((x >= y) | 0) != (y | 0)) | 0)))) >>> Math.fround(( + mathy3(Math.cosh(mathy3(Math.fround(Math.max((x | 0), mathy3(1, 2**53))), (Math.acosh(y) | 0))), (Math.pow(( + ( - (0x0ffffffff >>> 0))), y) ? y : mathy1(y, x)))))))); }); testMathyFunction(mathy4, [0x100000000, 1, 0x0ffffffff, Math.PI, -Number.MAX_VALUE, 42, -(2**53+2), -(2**53-2), 0x080000001, -0x080000001, 0/0, -0x100000000, 1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53, -1/0, -0x0ffffffff, -0, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, -(2**53), 0x07fffffff, 2**53-2, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-248247344*/count=872; tryItOut("h0 = a0[17];");
/*fuzzSeed-248247344*/count=873; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.ceil(Math.fround(Math.trunc(( - (y > x))))) , (( + (( - mathy2(Math.hypot(-0x07fffffff, x), x)) == ((Math.acosh(( + x)) <= mathy0(Math.fround(x), Math.fround(-Number.MAX_VALUE))) >>> 0))) >>> 0)); }); testMathyFunction(mathy3, [0, -0x080000000, -(2**53), -(2**53-2), 0.000000000000001, 42, 2**53+2, 0x100000001, 2**53, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x080000001, 1, 1/0, 0x080000000, -Number.MAX_VALUE, -0x100000000, -0x0ffffffff, 0x07fffffff, -0, Math.PI, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, -1/0, 1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=874; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.log(( + (( ~ (mathy1((( + Math.hypot(y, Math.min(y, x))) >= ( + (Math.expm1((y >>> 0)) >>> 0))), (y < ( + (Math.fround(y) ? (x | 0) : Math.fround(( - y)))))) | 0)) | 0))); }); testMathyFunction(mathy5, [0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, -(2**53), -0x0ffffffff, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 42, Number.MIN_VALUE, 0/0, 0x080000001, 2**53, 1.7976931348623157e308, -0, -0x100000000, -0x080000000, -(2**53-2), -Number.MAX_VALUE, 0x100000000, -1/0, 2**53+2, Math.PI, Number.MAX_VALUE, 0x07fffffff, 0, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=875; tryItOut("testMathyFunction(mathy1, [1/0, -0x080000001, 2**53, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0x100000001, -(2**53+2), 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 1, -(2**53), -0x100000000, 42, -1/0, 0/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, 0x080000000, -(2**53-2), -0x100000001, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, Number.MAX_VALUE, Math.PI, 2**53-2, 0x080000001, -0x07fffffff, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-248247344*/count=876; tryItOut("/*RXUB*/var r = new RegExp(\"(?!.*)\", \"m\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=877; tryItOut("mathy5 = (function(x, y) { return Math.trunc(Math.fround(Math.sin(Math.fround(Math.atanh(mathy3((y | 0), (-(2**53+2) | 0))))))); }); testMathyFunction(mathy5, [(new Number(0)), (function(){return 0;}), '/0/', ({valueOf:function(){return '0';}}), -0, (new Boolean(true)), true, [0], NaN, null, 1, (new Boolean(false)), '0', objectEmulatingUndefined(), 0.1, ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return 0;}}), '\\0', false, undefined, [], (new Number(-0)), 0, '', (new String(''))]); ");
/*fuzzSeed-248247344*/count=878; tryItOut("var b = (uneval(Math.atanh(Int8Array(arguments)))), x, this.x = x, e, c = x;g1 + e0;");
/*fuzzSeed-248247344*/count=879; tryItOut("g2.offThreadCompileScript(\"function f1(e1) \\\"use asm\\\";   var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    switch ((((0xda46685c) / (0x203ff98c)) | (((Float64ArrayView[((0xd5e1c28)) >> 3]))))) {\\n    }\\n    return +((+(0.0/0.0)));\\n  }\\n  return f;\");");
/*fuzzSeed-248247344*/count=880; tryItOut("");
/*fuzzSeed-248247344*/count=881; tryItOut("\"use asm\"; neuter(b2, \"change-data\");");
/*fuzzSeed-248247344*/count=882; tryItOut("o0 = new Object;");
/*fuzzSeed-248247344*/count=883; tryItOut("{let(zvegwu, x, y, x, x, bmqqaz) { return Object.defineProperty(a, \"constructor\", ({get: String.fromCodePoint, set: encodeURIComponent, enumerable: this}));} }");
/*fuzzSeed-248247344*/count=884; tryItOut("mathy0 = (function(x, y) { return (a) =  /x/ ; }); testMathyFunction(mathy0, [42, -1/0, -(2**53), 0.000000000000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, 0x100000001, 2**53, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, 0x080000000, 1.7976931348623157e308, Math.PI, -0x0ffffffff, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, 1, 0/0, -Number.MIN_VALUE, -0, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 0, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-248247344*/count=885; tryItOut("\"use asm\"; ltottq, {w: [], x: [NaN, , ], x: \u3056, y, window, d: {of: e, x, a: ({})}, x: y, w: b} = ((4277) = ((function too_much_recursion(olqpqn) { /*tLoop*/for (let x of /*MARR*/[[]]) { g1.h0.fix = (function() { try { t0 = new Uint32Array(v0); } catch(e0) { } print(e0); return s1; }); }; if (olqpqn > 0) { ; too_much_recursion(olqpqn - 1);  } else {  }  })(81657))), x = (4277), x, rrtbmx, {window: {this.zzz.zzz: [, {e}]}, x: eval, NaN, c: []} = true, b = false, window, x = x;print(x);");
/*fuzzSeed-248247344*/count=886; tryItOut("mathy2 = (function(x, y) { return (Math.log((Math.fround(Math.min((((2**53 | 0) && (( + ((Math.atan((((x >>> 0) , ( + (( - y) | 0))) >>> 0)) | 0) & (( + ( ~ ( + x))) | 0))) | 0)) | 0), ( ! ((mathy1(y, x) ? (y | 0) : Math.fround(( ! Math.fround(Math.pow(y, x))))) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 0x100000000, -0, -0x080000000, 0.000000000000001, 0x0ffffffff, 0x07fffffff, 0x080000000, -Number.MIN_VALUE, 0, 0/0, 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 2**53, -0x100000000, 1/0, -0x07fffffff, -0x100000001, Number.MAX_VALUE, -(2**53), 1, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=887; tryItOut("\"use strict\"; /*infloop*/ for  each(x in Object.prototype.propertyIsEnumerable) {print(x); }");
/*fuzzSeed-248247344*/count=888; tryItOut(" for  each(let z in let (y = this) [1]) let(x) { x.constructor;}");
/*fuzzSeed-248247344*/count=889; tryItOut("\"use strict\"; this.v1 = Object.prototype.isPrototypeOf.call(m1, this.s0);");
/*fuzzSeed-248247344*/count=890; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( + Math.imul(( + mathy1(( ~ y), ( ! x))), (x << mathy1(-(2**53+2), y)))), ( + Math.fround(Math.pow((Math.sign((mathy1((x > 0/0), (y << (Math.log1p(Math.fround(x)) | 0))) >>> 0)) | 0), (( + mathy0(( + x), ( + (mathy1((x | 0), (Math.atan((Math.cosh(y) >>> 0)) | 0)) | 0)))) | 0))))); }); testMathyFunction(mathy2, [-1/0, -0x100000001, 1, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, 0x100000000, -(2**53+2), Number.MIN_VALUE, 2**53+2, Math.PI, 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 0, -0, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, 42, -Number.MAX_VALUE, 0x100000001, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0x080000001, 1/0, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=891; tryItOut("true;\nt1.set(a0, 4);\n");
/*fuzzSeed-248247344*/count=892; tryItOut("testMathyFunction(mathy0, [-Number.MIN_VALUE, 0, -0x07fffffff, 0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, 1/0, -0, 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, 0x080000000, 0/0, -0x100000000, 2**53+2, Math.PI, -1/0, -(2**53-2), 0x100000001, 0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 42, -0x080000000, 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-248247344*/count=893; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.sinh((( - (mathy1(((( + x) ^ ((mathy0((Math.tan(x) | 0), (Math.min(-0x100000001, 0x080000000) | 0)) | 0) >>> 0)) >>> 0), Math.PI) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [1/0, 0x07fffffff, 2**53, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, 1, -0x100000000, -(2**53), -0x080000001, -Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, 0x080000000, -0, -Number.MAX_VALUE, 0x0ffffffff, 2**53+2, Number.MIN_VALUE, -1/0, 0.000000000000001, 0/0, -(2**53+2), Number.MAX_VALUE, 2**53-2, 0x080000001, -0x100000001]); ");
/*fuzzSeed-248247344*/count=894; tryItOut("\"use strict\"; /*infloop*/M:for(Math.acos( /* Comment */null); Math.min( \"\" , -4); 6.UTC()) f2 = Proxy.createFunction(h1, f2, f0);");
/*fuzzSeed-248247344*/count=895; tryItOut("v2 = g0.eval(\"m2.set(t0, b2);\");");
/*fuzzSeed-248247344*/count=896; tryItOut("o0.i1.next();");
/*fuzzSeed-248247344*/count=897; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[x, x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, arguments.caller, arguments.caller, arguments.caller, arguments.caller, [1], objectEmulatingUndefined(), x, [1], [1], x, arguments.caller, x, objectEmulatingUndefined(), [1], arguments.caller, x, x, x, x, [1], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, [1], arguments.caller, arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, [1], arguments.caller, objectEmulatingUndefined(), [1], objectEmulatingUndefined(), x, arguments.caller, x, [1], arguments.caller, [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, [1], [1], objectEmulatingUndefined(), x, [1], [1], objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, arguments.caller, [1], arguments.caller, arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, [1], arguments.caller, x, [1], x, arguments.caller, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, x, [1], arguments.caller, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), [1], arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, arguments.caller, arguments.caller, arguments.caller, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined()]) { /*infloop*/for(let x; ++z; Math.pow(x, (a.eval(\"/* no regression tests found */\")))) {for (var p in s0) { try { var v0 = a1.length; } catch(e0) { } v1 = r0.exec; } }\nfunction shapeyConstructor(ujatmi){this[new String(\"12\")] =  /x/ ;delete this[new String(\"12\")];Object.defineProperty(this, \"setUint8\", ({set: window, configurable: false}));Object.defineProperty(this, new String(\"12\"), ({configurable: true, enumerable: false}));this[new String(\"12\")] = -11;this[new String(\"12\")] = ujatmi;Object.seal(this);return this; }/*tLoopC*/for (let z of /*MARR*/[ /x/ , -1, -1, -1,  /x/ , -(2**53), -1, -1, -(2**53), -(2**53),  /x/ , -(2**53), -(2**53), -(2**53), -(2**53),  /x/ , -1, -1]) { try{let rddweg = new shapeyConstructor(z); print('EETT'); Array.prototype.push.call(a1, h1,  /x/g , b0);}catch(e){print('TTEE ' + e); } }\n }");
/*fuzzSeed-248247344*/count=898; tryItOut("let a = new -28(/(?=\\B\\w|\\u008D{3,})?|\\w{1023,1024}/ym);( /x/ );");
/*fuzzSeed-248247344*/count=899; tryItOut("\"use strict\"; \"use asm\"; a2 = Array.prototype.slice.call(this.a0, NaN, NaN);function window()arguments.callee.caller.arguments = \nx = (makeFinalizeObserver('nursery'))g1.v0 = g2.runOffThreadScript();");
/*fuzzSeed-248247344*/count=900; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x080000001, 2**53, 0x0ffffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 1/0, 0x100000001, 1, 0x100000000, 0.000000000000001, -0x07fffffff, 42, 2**53-2, -0x100000001, 1.7976931348623157e308, -(2**53+2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 2**53+2, 0/0, 0x080000001, 0x080000000, -0, -(2**53), -0x100000000, -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-248247344*/count=901; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-248247344*/count=902; tryItOut("v2 = Object.prototype.isPrototypeOf.call(b1, s0);");
/*fuzzSeed-248247344*/count=903; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(( + ( + ((mathy0(x, ( + (Math.fround(y) / Math.fround(Math.hypot(Math.fround(y), ( + x)))))) | 0) || (Math.hypot((x >>> 0), (x >>> 0)) >>> 0)))), ((( + (( ~ (y >>> 0)) >>> 0)) | 0) >>> 0))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, Number.MAX_VALUE, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 2**53-2, 1.7976931348623157e308, 0x07fffffff, 0/0, -0x080000000, 42, 0x080000001, 2**53+2, -0x080000001, -0x0ffffffff, Number.MIN_VALUE, -0, -(2**53+2), 2**53, -0x07fffffff, -0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, 1, 1/0, 0x0ffffffff, Math.PI, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=904; tryItOut("\"use strict\"; with({a: ( \"\" .watch(\"call\", offThreadCompileScript))})o0.b0.__proto__ = v1;");
/*fuzzSeed-248247344*/count=905; tryItOut("\"use strict\"; L: v2 = evaluate(\"function f1(p2)  { yield \\\"\\\\u9F06\\\" } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: \"\\u5F30\" }));a0.splice(NaN, ({valueOf: function() { Array.prototype.pop.call(a1, this.a1);return 14; }}));");
/*fuzzSeed-248247344*/count=906; tryItOut("/*oLoop*/for (jmokyq = 0, NaN = ((0/0)); jmokyq < 28; ++jmokyq) { print(this.__defineSetter__(\"window\", ( \"\" ).call)); } ");
/*fuzzSeed-248247344*/count=907; tryItOut("\"use strict\"; s0 = new String(this.v0);");
/*fuzzSeed-248247344*/count=908; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.tanh((y !== x)) | 0) > ( + Math.fround(( + Math.fround(mathy2(Math.fround(-1/0), Math.fround(Math.fround(Math.trunc(Math.fround(Math.imul(y, y))))))))))) ? mathy0(Math.fround(((( + (y >>> 0)) >>> 0) ? y : ( + ( ~ Math.atan(Math.fround(((x ^ y) | 0))))))), Math.atan((y >>> 0))) : (Math.fround(Math.min((x >>> 0), (y >>> 0))) ? (( + ( ! ( + ((Math.sin(x) >>> 0) / (Math.acos(y) >>> 0))))) | 0) : Math.atan2(x, ( + (y !== y))))); }); testMathyFunction(mathy3, [-0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -Number.MIN_VALUE, -0, 2**53-2, 0x100000001, 42, 1.7976931348623157e308, 1, 1/0, 0x07fffffff, 0/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), -(2**53), -0x100000001, 0x0ffffffff, -1/0, -0x080000000, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, -(2**53+2), Math.PI]); ");
/*fuzzSeed-248247344*/count=909; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; void schedulegc(48); } void 0; } a2 = r2.exec(s2);");
/*fuzzSeed-248247344*/count=910; tryItOut("/*RXUB*/var r = 16; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=911; tryItOut("\"use strict\"; while((--w) && 0){v0 = Object.prototype.isPrototypeOf.call(this.i2, m2); }");
/*fuzzSeed-248247344*/count=912; tryItOut("\"use strict\"; x = x;x.fileName;");
/*fuzzSeed-248247344*/count=913; tryItOut("var x = URIError(w = NaN, (Math.tanh(-3)));v0 = (this.v0 instanceof g2);");
/*fuzzSeed-248247344*/count=914; tryItOut("\"use strict\"; s2 += 'x';\n/* no regression tests found */\n");
/*fuzzSeed-248247344*/count=915; tryItOut("switch('fafafa'.replace(/a/g, neuter) += (window.lastIndexOf(/\\3/m\u000c))) { case this.__defineSetter__(\"arguments[18]\", function shapeyConstructor(zeoalb){this[6] = q => q;Object.defineProperty(this, 6, ({get: function(y) { \"use strict\"; return this }, configurable:  '' , enumerable: false}));Object.freeze(this);this[6] = Date(/\\3|(?=.{4}[^](?=(?=\\B)))?/yi, null);return this; }): case (/(?:[^]+?|\\r?($))+?|(?!\ud2f8){3,5}+/g , true): h1 + o0.a0;new RegExp(\"(?:^([\\\\u64b2\\\\b-\\\\n\\\\d\\\\u00EE-\\\\u00ff])?|.)|(?:[^]\\\\S+)?\", \"yi\")/*\n*/;default: a0 + g2.h2;break; case 3: a0.splice(15, v1, a0); }");
/*fuzzSeed-248247344*/count=916; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=917; tryItOut("o0.toSource = (function() { try { v2 = Object.prototype.isPrototypeOf.call(g2, t1); } catch(e0) { } g1.offThreadCompileScript(\"((makeFinalizeObserver('nursery')))\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: /*FARR*/[...((4277) for ((y) in (function ([y]) { })()) for each (e in 18))].map((Math.acos).apply), noScriptRval: function ([y]) { }, sourceIsLazy: false, catchTermination: (x % 4 == 0) })); return b2; });");
/*fuzzSeed-248247344*/count=918; tryItOut("\"use strict\"; for(let c in  /x/ ) {(null); }");
/*fuzzSeed-248247344*/count=919; tryItOut("mathy0 = (function(x, y) { return Math.cbrt(( ! Math.fround(((( ~ (x / x)) | 0) !== ( ! ( + Math.cosh(0x080000001))))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 2**53-2, -1/0, 0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), -(2**53), 0.000000000000001, 0/0, -0x100000001, -0, 2**53+2, Number.MIN_VALUE, -0x080000001, 1, 0x0ffffffff, 2**53, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, 42, 0x100000001, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=920; tryItOut("(makeFinalizeObserver('nursery'));");
/*fuzzSeed-248247344*/count=921; tryItOut("\"use strict\"; v2 = (h0 instanceof g1);");
/*fuzzSeed-248247344*/count=922; tryItOut("i2 = new Iterator(f1);");
/*fuzzSeed-248247344*/count=923; tryItOut("/*RXUB*/var r = /(?!\\2)/yi; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=924; tryItOut("\"use strict\"; o1.e0.has(v1);");
/*fuzzSeed-248247344*/count=925; tryItOut("\"use asm\"; /*oLoop*/for (var rljnvz = 0; rljnvz < 50; ++rljnvz) { /*infloop*/M:for(x;  '' [\"caller\"] = /*UUV1*/(x.getFloat64 = decodeURIComponent); yield let (d)  '' ) ((function ([y]) { })());arguments; } ");
/*fuzzSeed-248247344*/count=926; tryItOut("this.f0 = (function() { Array.prototype.forEach.call(a0, (function() { try { ; } catch(e0) { } try { i2 = new Iterator(a2, true); } catch(e1) { } m2.toSource = (function() { try { g1.i0 = new Iterator(o2.i2); } catch(e0) { } Array.prototype.unshift.apply(o1.a1, []); return f2; }); return m0; })); return f0; });");
/*fuzzSeed-248247344*/count=927; tryItOut("for (var v of g1) { try { /*ADP-2*/Object.defineProperty(a2, ({valueOf: function() { v2 = Object.prototype.isPrototypeOf.call(g1, g2);return 15; }}), { configurable: false, enumerable: (x % 5 == 0), get: (function() { try { this.v0 = Math.atan2([,,z1], 9); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(g0.g0, v1); } catch(e1) { } try { t1.__proto__ = a1; } catch(e2) { } let o2 = new Object; return this.g0; }), set: (function(j) { if (j) { try { e1.__iterator__ = (function() { for (var j=0;j<45;++j) { f0(j%2==0); } }); } catch(e0) { } try { e2.has(a0); } catch(e1) { } try { o2.e2 = this.t2[19]; } catch(e2) { } a1 + this.b0; } else { try { t1 = new Float64Array(({valueOf: function() { g0.a2 = a0.slice(-2, -3, x);return 3; }})); } catch(e0) { } try { o0.a2.splice(p1, this.g1, /*MARR*/[ '\\0' ,  '\\0' , false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,  '\\0' ,  /x/g ,  '\\0' ,  '\\0' , false, false, false, false, false,  '\\0' , false,  '\\0' , false,  '\\0' , false, false,  '\\0' , false,  /x/g ,  '\\0' ,  '\\0' ,  '\\0' , false, false, false,  '\\0' ,  /x/g , false,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  /x/g ,  /x/g , false,  '\\0' ,  '\\0' ,  '\\0' ,  /x/g ,  /x/g ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  /x/g , false,  '\\0' ,  '\\0' , false,  /x/g ,  '\\0' ,  '\\0' ,  '\\0' , false,  '\\0' ,  /x/g ,  /x/g , false, false,  '\\0' , false, false].some(Math.clz32(\"\u03a0\"))); } catch(e1) { } o2.v2 = null; } }) }); } catch(e0) { } try { s0 = Array.prototype.join.apply(a2, [s1, o0, i0]); } catch(e1) { } i2.send(h0); }");
/*fuzzSeed-248247344*/count=928; tryItOut("\"use asm\"; a0 = r1.exec(s0);");
/*fuzzSeed-248247344*/count=929; tryItOut("mathy0 = (function(x, y) { return ((Math.asin(Math.fround(Math.asin(((x ? y : ( + Math.atan2((x | 0), (Math.imul(Math.fround(y), (0x100000001 | 0)) | 0)))) >>> 0)))) >>> 0) , (Math.log2((Math.imul(Math.fround((( + ( - Math.cos(-0))) == 1)), Math.fround(Math.imul(Math.fround(Math.atan2(y, x)), Math.fround(-Number.MIN_SAFE_INTEGER)))) <= Math.fround((Math.fround(( - ( ~ x))) ? Math.fround(x) : ( + Math.atan2(2**53+2, (x | 0))))))) >>> 0)); }); testMathyFunction(mathy0, [1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, -(2**53), -1/0, Number.MAX_VALUE, -0, 2**53-2, 2**53, Number.MIN_VALUE, 2**53+2, Math.PI, 1, 0x07fffffff, -0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, -0x080000000, 0x100000000, -(2**53+2), 0/0, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -(2**53-2), 0.000000000000001, 0x080000001, -Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-248247344*/count=930; tryItOut("v2 = (b0 instanceof a0);");
/*fuzzSeed-248247344*/count=931; tryItOut("a1.push(\"\\u0E9F\", b2, b1);");
/*fuzzSeed-248247344*/count=932; tryItOut("mathy0 = (function(x, y) { return ((Math.cbrt((Math.exp((( + ((2**53+2 | 0) & (y | 0))) >>> 0)) >>> 0)) >>> 0) / (((( + Math.cosh(( + Math.fround(Math.atan(( + (( + (Math.atanh(y) || x)) , ( + x)))))))) >>> 0) >> ((Math.acos((Math.asinh(Math.fround(Math.atan2(( + Math.min(-0x100000001, ( + x))), ((Math.fround(y) , ((x % y) | 0)) | 0)))) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, ['0', /0/, false, true, (new Number(0)), ({valueOf:function(){return 0;}}), '/0/', ({valueOf:function(){return '0';}}), undefined, (new String('')), (new Number(-0)), NaN, (new Boolean(true)), -0, 0.1, '\\0', (function(){return 0;}), [], 0, '', 1, [0], null, objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new Boolean(false))]); ");
/*fuzzSeed-248247344*/count=933; tryItOut("mathy4 = (function(x, y) { return (Math.fround(Math.log2(((Math.fround((Math.max((((y | 0) <= (42 | 0)) >>> 0), (x | 0)) | 0)) ** (x >>> 0)) != ( + ( + Math.pow(( + x), ( + ((42 >= (x | 0)) | 0)))))))) * mathy1(( + (y !== (Math.sinh(x) | 0))), ( ! (Math.round((( + Math.expm1(( + x))) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [1/0, 1.7976931348623157e308, 0/0, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 42, -(2**53+2), 0x080000001, Math.PI, -0x100000001, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, -1/0, 0x07fffffff, -(2**53-2), 2**53-2, 0, -0x100000000, Number.MAX_VALUE, -0x080000001, -Number.MAX_VALUE, 0x100000000, -0x0ffffffff, -0x07fffffff, -0x080000000, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=934; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ (Math.imul(((( ! (( + ( - (x | 0))) >>> 0)) >>> 0) ** 0), ( - ( - (y % (Math.max((Number.MIN_SAFE_INTEGER | 0), (y | 0)) ? x : y))))) >>> 0)); }); testMathyFunction(mathy2, [NaN, 1, (function(){return 0;}), '0', (new Boolean(false)), (new String('')), false, '\\0', [], true, [0], (new Number(-0)), ({valueOf:function(){return 0;}}), undefined, (new Number(0)), ({toString:function(){return '0';}}), objectEmulatingUndefined(), 0, /0/, (new Boolean(true)), -0, null, '/0/', 0.1, ({valueOf:function(){return '0';}}), '']); ");
/*fuzzSeed-248247344*/count=935; tryItOut("\"use strict\"; /*oLoop*/for (var vyodat = 0; (window) && ( /x/ ) && vyodat < 1; ++vyodat) { e0.add(false); } ");
/*fuzzSeed-248247344*/count=936; tryItOut("\"use strict\"; e1 = new Set;");
/*fuzzSeed-248247344*/count=937; tryItOut("for (var p in t2) { try { m2 = new WeakMap; } catch(e0) { } try { selectforgc(g0.o0); } catch(e1) { } try { h1 = ({getOwnPropertyDescriptor: function(name) { h0.__iterator__ = f2;; var desc = Object.getOwnPropertyDescriptor(o1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { Object.defineProperty(this, \"a1\", { configurable: false, enumerable: false,  get: function() {  return []; } });; var desc = Object.getPropertyDescriptor(o1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(e1);; Object.defineProperty(o1, name, desc); }, getOwnPropertyNames: function() { return b2; return Object.getOwnPropertyNames(o1); }, delete: function(name) { return f0; return delete o1[name]; }, fix: function() { v2 = evaluate(\"this.a2 = a2.map((function(stdlib, foreign, heap){ \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var abs = stdlib.Math.abs;\\n  var ff = foreign.ff;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    return +((Float32ArrayView[((((i1))>>>(((~((0xffffffff))) < (imul((0x8ad44576), (0xd5638ed8))|0))-((((0xeec5faf6)) | ((0xfd4798c6))) != (abs((0x127873b8))|0)))) / (((abs((abs((0x5b3d7cde))|0))|0) / (abs((((0xfeef4f5d))|0))|0))>>>(-0x8a9f9*(-0x8000000)))) >> 2]));\\n  }\\n  return f; })(this, {ff: function  w (d) { yield window instanceof x } }, new ArrayBuffer(4096)));\", ({ global: o0.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 != 2), noScriptRval: false, sourceIsLazy: (x % 3 != 2), catchTermination: (x % 6 != 4) }));; if (Object.isFrozen(o1)) { return Object.getOwnProperties(o1); } }, has: function(name) { v1 = null;; return name in o1; }, hasOwn: function(name) { for (var v of t2) { try { g0.h1.fix = (function(j) { if (j) { try { o2.h2.set = f1; } catch(e0) { } i1 = a1.values; } else { try { Array.prototype.sort.call(a0, (function(j) { f0(j); }), h2, s0); } catch(e0) { } a2.splice(NaN, v2, let (w)  '' , e1); } }); } catch(e0) { } ; }; return Object.prototype.hasOwnProperty.call(o1, name); }, get: function(receiver, name) { return o1; return o1[name]; }, set: function(receiver, name, val) { e0.add(f0);; o1[name] = val; return true; }, iterate: function() { v2 = g1.a2.length;; return (function() { for (var name in o1) { yield name; } })(); }, enumerate: function() { this.v2 = Object.prototype.isPrototypeOf.call(p0, g2);; var result = []; for (var name in o1) { result.push(name); }; return result; }, keys: function() { Object.defineProperty(this, \"v0\", { configurable: (x % 5 != 2), enumerable: x,  get: function() {  return evalcx(\"window\", g1); } });; return Object.keys(o1); } }); } catch(e2) { } const v0 = t2.length; }");
/*fuzzSeed-248247344*/count=938; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (( + ( + ( - ( + ( ~ ( ! x)))))) << ( + (Math.cosh((( + (( ~ x) >>> 0)) !== Math.max((( ! Math.expm1((0x100000000 >> -0x100000000))) >>> 0), (((((Math.imul((x | 0), (y >>> 0)) | 0) | 0) ** (y | 0)) >>> 0) != y)))) >>> 0)))); }); testMathyFunction(mathy1, [0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0, 1.7976931348623157e308, 0x0ffffffff, 1, -0x080000000, -(2**53), -0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, -0, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 2**53+2, 0x100000001, -(2**53+2), 1/0, Math.PI, Number.MIN_VALUE, -0x080000001, -0x100000001, 0x07fffffff, 0x080000001, 42, 2**53, -Number.MIN_SAFE_INTEGER, -1/0, 0/0]); ");
/*fuzzSeed-248247344*/count=939; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! Math.atan2((Math.ceil((mathy0(y, -0x100000001) >>> 0)) >>> 0), (Math.expm1(( - Math.fround(((( - (2**53+2 | 0)) | 0) <= Math.fround(-0x07fffffff))))) >>> 0))); }); testMathyFunction(mathy2, [2**53, 2**53-2, -(2**53+2), -0x07fffffff, 0x07fffffff, -0x080000001, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 1, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, Math.PI, 0x080000000, -Number.MAX_VALUE, -(2**53), -0x080000000, 42, 0x0ffffffff, 0x080000001, -0x100000001, -(2**53-2), 0x100000001, -1/0, Number.MAX_VALUE, 2**53+2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, 0/0, 0.000000000000001, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=940; tryItOut("/*bLoop*/for (let hldnlx = 0; hldnlx < 114; ++hldnlx) { if (hldnlx % 67 == 44) { s2 += 'x'; } else { v1 = evaluate(\"m1.delete(this);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 == 1), sourceIsLazy: true, catchTermination: false })); }  } ");
/*fuzzSeed-248247344*/count=941; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.imul(((Math.fround((y <= Math.fround(Math.hypot(y, x)))) >>> 0) > (((( + Math.cosh(y)) | 0) >= x) | 0)), (y << (( + ( + ( ~ (Number.MAX_SAFE_INTEGER != Math.fround(x))))) - (Math.min((Math.tanh(0/0) | 0), y) >>> 0)))) || ( + ((( + (( ~ (Math.atan((Math.sin(x) >>> 0)) >>> 0)) >>> 0)) >>> 0) < (( ~ y) ^ (( ~ (-0x100000000 >>> 0)) >>> 0))))) | 0); }); testMathyFunction(mathy0, [-(2**53-2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, -0x080000001, 1, -Number.MAX_VALUE, -0x080000000, -(2**53+2), 0x07fffffff, -0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -(2**53), -0x100000000, 1.7976931348623157e308, -0x100000001, Number.MAX_VALUE, 2**53+2, 2**53-2, 0x080000000, 0x100000001, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -0, 0/0, -0x0ffffffff, 0, 1/0, Math.PI]); ");
/*fuzzSeed-248247344*/count=942; tryItOut("print(t0);function a()((void version(185)))print(x);");
/*fuzzSeed-248247344*/count=943; tryItOut("/*vLoop*/for (let rusbfo = 0; rusbfo < 17; ++rusbfo) { var a = rusbfo; a0 = []; } ");
/*fuzzSeed-248247344*/count=944; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - (( + mathy1(Math.abs((( ! ((((x >>> 0) | (( + x) >>> 0)) >>> 0) >>> 0)) >>> 0)), ( + ((( + ( ~ ((( ~ Math.fround(x)) | 0) ? x : Number.MIN_SAFE_INTEGER))) | 0) ** ( + (mathy0(x, 0x07fffffff) + Math.sign(-0x100000001))))))) | 0)); }); testMathyFunction(mathy3, [1, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 2**53, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, 42, -Number.MIN_VALUE, 2**53+2, 0x100000000, -0, 0/0, -0x080000001, 0x100000001, -(2**53), Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 0, 0x080000001, 1/0, -0x100000000, -(2**53+2), 0.000000000000001, -(2**53-2), 0x080000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=945; tryItOut("i1.send(i2);");
/*fuzzSeed-248247344*/count=946; tryItOut("mathy0 = (function(x, y) { return Math.atan2(( + Math.pow(( + (( - ((((x ** Number.MIN_SAFE_INTEGER) | 0) & y) | 0)) | 0)), ( + Math.min(( ~ 1.7976931348623157e308), ((( + Math.imul(( + ( ! Math.min(x, y))), (((Math.pow(Math.fround(x), ( + y)) >>> 0) > Math.log(y)) | 0))) == ( + Math.log1p((x >>> 0)))) >>> 0))))), (Math.expm1((Math.atan2(( + Math.atan2(Math.trunc(Number.MIN_SAFE_INTEGER), y)), (y ? -0 : ( + (( + -0x100000000) ? ( + y) : ( + x))))) / Math.hypot(Math.log2((y ? (x >>> 0) : (x >>> 0))), ( + (( + x) === ( + y)))))) | 0)); }); ");
/*fuzzSeed-248247344*/count=947; tryItOut("v0 = (h0 instanceof b0);");
/*fuzzSeed-248247344*/count=948; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (mathy0(( + (( + -0x100000000) ? ( + (Math.fround(( ! Math.fround(-0x080000000))) == ( ! x))) : (Math.sign(( ! ( + Math.atan2(( + y), ( + (x && y)))))) >>> 0))), ((Math.imul(Math.fround(Math.expm1(Math.fround(y))), (x | 0)) | 0) | 0)) | 0)); }); ");
/*fuzzSeed-248247344*/count=949; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy1((Math.pow(Math.atan2(Math.fround((Math.hypot(( + 0x0ffffffff), ( + x)) | (Number.MAX_SAFE_INTEGER >>> 0))), ((((x * ((( ! (x >>> 0)) >>> 0) | 0)) | 0) >>> 0) > ( ! Math.pow(x, y)))), Math.pow(( + ( + Math.fround(-0x0ffffffff))), ( + ( + x)))) | 0), Math.round(Math.exp(mathy1(Math.fround(( + Math.sin((Math.pow(((Math.pow((y | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0) | 0), (y | 0)) | 0)))), Math.sin((x >>> 0)))))); }); testMathyFunction(mathy3, [-0x080000001, 0x0ffffffff, 0/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, 2**53, Math.PI, -Number.MIN_VALUE, 0x080000001, -0, -0x100000001, Number.MIN_VALUE, -0x080000000, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, 2**53+2, 0x100000000, 42, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, -(2**53+2), 0, 0x100000001, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=950; tryItOut("\"use strict\"; /*MXX3*/g2.RegExp.prototype.test = g1.RegExp.prototype.test;");
/*fuzzSeed-248247344*/count=951; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ! Math.atan(Math.fround(( ! Math.fround((( + x) - (( + Math.atan2(x, y)) >>> 0))))))) >>> 0); }); ");
/*fuzzSeed-248247344*/count=952; tryItOut("testMathyFunction(mathy3, [-(2**53+2), 1, -0, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 2**53, 0/0, -0x080000000, -0x100000000, 2**53+2, -1/0, 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 42, 0, Number.MAX_VALUE, 0x080000001, 0x100000001, 0x0ffffffff, -(2**53), 0.000000000000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 2**53-2, 1/0, 0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=953; tryItOut(";");
/*fuzzSeed-248247344*/count=954; tryItOut("\"use strict\"; for (var p in b0) { Array.prototype.unshift.apply(a2, [o0.a1, m2, a1]); }\n\"\\u4C54\";\n");
/*fuzzSeed-248247344*/count=955; tryItOut("mathy0 = (function(x, y) { return ( ~ (Math.fround(( ! ((y ? Math.imul(y, x) : Math.hypot(( + Math.asinh(( + y))), x)) | 0))) | (Math.log((Math.atan2(( + Math.max(y, y)), ( + Math.clz32(( + 2**53+2)))) >>> 0)) != ((((x ? ((Math.imul((x >>> 0), (x >>> 0)) >>> 0) === (x != x)) : x) | 0) !== (( - Math.abs(x)) | 0)) | 0)))); }); ");
/*fuzzSeed-248247344*/count=956; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, new Number(1.5), new Number(1.5), Infinity, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), Infinity, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]) { e1.toSource = (function() { try { a0.push(s2,  /x/ , h2); } catch(e0) { } try { print(t0); } catch(e1) { } (void schedulegc(g0)); throw t0; }); }");
/*fuzzSeed-248247344*/count=957; tryItOut("( '' );function window() { yield (e = x) >>>= b } \u000cArray.prototype.forEach.call(a2, (function(j) { g2.f0(j); }));");
/*fuzzSeed-248247344*/count=958; tryItOut("print(x);");
/*fuzzSeed-248247344*/count=959; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.fround(Math.atan(( ~ Math.clz32(-0x100000000))))); }); testMathyFunction(mathy2, [1/0, 0x100000000, 2**53-2, -(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -0x080000001, -1/0, 0x100000001, 0x07fffffff, 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, Math.PI, -0x07fffffff, 42, -(2**53+2), -0, Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0x0ffffffff, 0, 1.7976931348623157e308, -0x080000000, -0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, 2**53]); ");
/*fuzzSeed-248247344*/count=960; tryItOut("\"use strict\"; var sgtxyn, hittzb, b, rtecik, NaN = ({} = \n /x/ ), [] = x, e = --x, x;Array.prototype.pop.apply(a0, [s1]);");
/*fuzzSeed-248247344*/count=961; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=962; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[new Boolean(false), arguments.callee, arguments.callee,  /x/g ,  /x/g , 0, 0, new Boolean(false), new Boolean(false),  /x/g ,  /x/g ]) { /*RXUB*/var r = /\\3/gy; var s = \"\\n\\u00ef\\n\"; print(s.split(r));  }");
/*fuzzSeed-248247344*/count=963; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy1((( ~ ((( ! -(2**53+2)) >>> y) | 0)) | 0), Math.fround((Math.sign(Math.log10((mathy1((Math.max(x, Math.fround((Math.fround((x && x)) === x))) | 0), (y | 0)) | 0))) | 0))); }); testMathyFunction(mathy3, [0x07fffffff, -(2**53), -(2**53-2), Number.MIN_VALUE, 2**53, 0/0, Math.PI, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, 2**53-2, 1, 0x100000001, 0x0ffffffff, 1/0, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -1/0, -0, 2**53+2, 0x080000000, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, 0.000000000000001, 0x100000000]); ");
/*fuzzSeed-248247344*/count=964; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.expm1((Math.atan2(( + Math.atan2(Math.expm1(y), y)), Math.fround((Math.abs(y) !== x))) >>> (((Math.log(x) | 0) ? ( + ( - (Math.exp((Math.fround(Math.tan(y)) | 0)) | 0))) : (x | 0)) | 0)))); }); ");
/*fuzzSeed-248247344*/count=965; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.tanh(( + ((( ! (Math.imul((( ~ -0x07fffffff) | 0), Math.fround(0.000000000000001)) >>> 0)) >>> 0) != Math.min(Math.fround((Math.hypot(((Math.fround((x > x)) ? (y >>> 0) : (Math.imul((Math.fround(mathy1((y >>> 0), (x >>> 0))) | 0), Math.fround(x)) | 0)) >>> 0), y) | 0)), Math.asin((mathy1(-1/0, (( - (Math.log1p(x) >>> 0)) >>> 0)) | 0)))))) | 0); }); testMathyFunction(mathy2, [-1/0, Number.MIN_SAFE_INTEGER, 2**53+2, 1, 0x100000001, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, -0x080000000, Number.MIN_VALUE, 1/0, 1.7976931348623157e308, -0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, 0/0, 0x080000000, 2**53-2, -(2**53), -(2**53+2), 0, 42, -Number.MAX_VALUE, 2**53, -0x100000000, -(2**53-2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=966; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.min(Math.fround(( + Math.ceil(x))), Math.fround(((((Math.max((y | 0), (0x100000000 | 0)) >>> 0) ^ (x >>> 0)) >>> 0) === y)))) >>> 0) , Math.hypot((Math.imul(x, (Math.cbrt((Math.min(x, 1/0) >>> 0)) >>> 0)) * ( + ((((x >>> 0) ^ (x >>> 0)) >>> 0) - ( + y)))), ( ~ Math.fround(Math.sqrt(x))))); }); testMathyFunction(mathy4, [({toString:function(){return '0';}}), (new String('')), ({valueOf:function(){return '0';}}), 0, -0, (new Number(-0)), '0', NaN, undefined, /0/, (new Boolean(false)), 0.1, (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Number(0)), '/0/', null, (new Boolean(true)), true, false, objectEmulatingUndefined(), [], 1, '\\0', '', [0]]); ");
/*fuzzSeed-248247344*/count=967; tryItOut("s2 = '';");
/*fuzzSeed-248247344*/count=968; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return (Math.asin((((( + (( + Math.tan(Math.tanh(( + y)))) >= ( + (x >> x)))) >>> 0) ^ ((( + (Math.acos(Math.expm1(y)) ? Math.fround(mathy0((mathy3(Math.pow(-0, -Number.MAX_SAFE_INTEGER), Math.fround(x)) >>> 0), y)) : x)) | Math.fround(Math.asin(Math.fround(mathy3(y, ( + y)))))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy4, [0.000000000000001, -0x100000000, -0x080000000, 1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, 1, 2**53, -Number.MAX_VALUE, 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0x080000000, -(2**53+2), 0/0, 42, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, -1/0, -0, -(2**53-2), -(2**53), -0x0ffffffff, -0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, 0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=969; tryItOut("\"use strict\"; s0[\"toString\"] = this.g0.a2;");
/*fuzzSeed-248247344*/count=970; tryItOut("\"use strict\"; t1.set(t0, 0);");
/*fuzzSeed-248247344*/count=971; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((Math.atan2(( + ( + Math.fround(( + Math.acos(( ~ Math.fround(x))))))), Math.max(( + Math.atan2((x | 0), (y | 0))), Math.min((x >>> (-Number.MAX_SAFE_INTEGER >>> 0)), ( - 0x080000001)))) >>> 0) ? Math.log(mathy0(Math.fround(Math.pow(Math.fround(x), Math.imul(x, x))), ( + Math.clz32(((Math.hypot((-0x080000000 >>> 0), (y >>> 0)) >>> 0) | 0))))) : (( + ((Math.fround((( ! ((x > (Math.atan2(x, x) ^ (y >>> 0))) >>> 0)) >>> 0)) ? ( + (( + mathy3((0/0 | 0), x)) / ( + y))) : Math.atan(Math.log10(Math.hypot(( ! x), y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [1/0, -0x0ffffffff, 0x07fffffff, -0x080000000, 2**53-2, 2**53+2, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), 0x080000000, 0x080000001, Math.PI, -0, 1, -0x07fffffff, 0x100000001, -1/0, -0x080000001, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0, Number.MAX_VALUE, -(2**53-2), -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 42]); ");
/*fuzzSeed-248247344*/count=972; tryItOut("mathy0 = (function(x, y) { return (((((((( + Math.log1p(( + -0x100000000))) / x) | 0) ? (Math.asin((( ~ ((-0x080000000 | ( + ( + ( + y)))) | 0)) | 0)) | 0) : ((Math.fround(( - ( + y))) | Math.fround(Number.MAX_VALUE)) >>> 0)) != Math.pow(((Math.log10(((y <= x) | 0)) >>> 0) / Math.fround(Math.fround((Math.fround(y) >= (y && x))))), ( + ( + (y | 0))))) >>> 0) > Math.fround(Math.min((( - ( + (Math.min(( + Math.log10(( + ( + x)))), ( + (Math.atan2(y, y) | 0))) == 0x100000001))) | 0), (( ~ ( + (0x0ffffffff ? ( + Math.min(y, Math.fround(( + (x | 0))))) : ( - x)))) | 0)))) >>> 0); }); ");
/*fuzzSeed-248247344*/count=973; tryItOut("\"use strict\"; { void 0; gcslice(1); } ;");
/*fuzzSeed-248247344*/count=974; tryItOut("\"use strict\"; /*RXUB*/var r = /[^]|(?:(?!\\2{16385}(?!^)G?))/yim; var s = null; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=975; tryItOut("\"use strict\"; v1 = (new Uint8ClampedArray(\u3056 < x, (void options('strict')))) >>> (delete z.NaN);");
/*fuzzSeed-248247344*/count=976; tryItOut("for(let a = (void shapeOf( '' )).throw(x) in (DFGTrue(/*RXUE*/new RegExp(\"[^]{1,}|(?:\\\\3*)+(?=[^])|((?!(?=[\\\\u00c4\\\\B-\\\\cT\\\\u001d-\\\\u00fd\\u8f7a-\\\\uA914]))){1}(?=\\\\S)|\\\\f$${0,}|\\\\3\", \"gyim\").exec(\"\\n\\n\\n\"),  /x/g )).__proto__ = (x = (Math.hypot( /x/g , \"\\u9094\")))) {/*infloop*/ for  each(let b in true) {return;o0.v0 = g2.eval(\"/* no regression tests found */\"); }v1 = Object.prototype.isPrototypeOf.call(t2, a0); }");
/*fuzzSeed-248247344*/count=977; tryItOut("\"use strict\"; /*hhh*/function rsgugu(...a){g2.m2.get(t2);function e(b)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -4294967297.0;\n    var i4 = 0;\n    var d5 = -2147483649.0;\n    i4 = (0x71504d92);\n    i0 = (0x4ae990f);\n    return +((-9.44473296573929e+21));\n  }\n  return f;m0.delete(i1);}rsgugu(x = x, (4277));");
/*fuzzSeed-248247344*/count=978; tryItOut("i1 = new Iterator(o2.t2);var d = delete window.b;");
/*fuzzSeed-248247344*/count=979; tryItOut("mathy1 = (function(x, y) { return Math.trunc(( - Math.tan((Math.min(Math.fround((( + Math.min(Math.fround(y), Math.fround(x))) ? x : Math.hypot(y, (y != y)))), Math.fround(Number.MAX_SAFE_INTEGER)) | 0)))); }); testMathyFunction(mathy1, [2**53+2, 0x100000000, 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, -0x080000001, Number.MIN_VALUE, -0x0ffffffff, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 1, 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, -0x100000000, -(2**53), 2**53-2, 0, 42, -0, 1/0, Math.PI]); ");
/*fuzzSeed-248247344*/count=980; tryItOut("/*oLoop*/for (dgwslb = 0; dgwslb < 66; ++dgwslb) { print(10); } ");
/*fuzzSeed-248247344*/count=981; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, -0x0ffffffff, Math.PI, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, 0x100000000, 0, -0, -(2**53), -0x100000001, 0x080000001, 1, 0x080000000, 0/0, -(2**53+2), -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, 42, 0.000000000000001, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, 0x100000001, 2**53+2, -Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-248247344*/count=982; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.exp(Math.fround(mathy3(Math.fround((mathy2(Math.fround(( + Math.fround(y))), (( + (( + Math.max((y >>> 0), x)) ** ( + y))) >>> 0)) >>> 0)), Math.fround((Math.fround(Math.pow((Math.min(((y >>> 0) < x), (Math.log2(x) | 0)) | 0), (((x + (0.000000000000001 >>> 0)) >>> 0) << x))) >>> 0)))))); }); ");
/*fuzzSeed-248247344*/count=983; tryItOut("\"use strict\"; {s2 += s2;{/*MXX1*/o2 = g0.SharedArrayBuffer; } }");
/*fuzzSeed-248247344*/count=984; tryItOut("for(var y = (x = Proxy.createFunction(({/*TOODEEP*/})(true), DataView.prototype.setFloat64, (function(y) { \"use strict\"; yield y; v0 = Object.prototype.isPrototypeOf.call(g1.a0, g1.v2);; yield y; }).bind())) in /(?!(?=(?=(?=[^]\\cY+?)))){4097,}/gi) {a0.__iterator__ = f1; }");
/*fuzzSeed-248247344*/count=985; tryItOut("\"use strict\"; t1 = t2.subarray(8);\nm0.toSource = Promise.prototype.catch.bind(i0);\n");
/*fuzzSeed-248247344*/count=986; tryItOut("Object.defineProperty(this, \"v1\", { configurable: false, enumerable: true,  get: function() {  return t1.length; } });");
/*fuzzSeed-248247344*/count=987; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(( - Math.atan2(( + (y * Math.fround(Math.acosh(Math.max(y, (x >>> 0)))))), (Math.fround(Math.fround(Math.exp(Math.fround(x)))) != mathy1(y, y)))))); }); testMathyFunction(mathy2, [-0x080000001, 0x100000001, 0x080000001, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, Math.PI, 2**53-2, -1/0, -0x100000000, Number.MIN_VALUE, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, -(2**53), 1, -(2**53-2), -0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, 1.7976931348623157e308, 1/0, -0x080000000, 0x07fffffff, 0x100000000, 0/0]); ");
/*fuzzSeed-248247344*/count=988; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; disableSPSProfiling(); } void 0; }");
/*fuzzSeed-248247344*/count=989; tryItOut("this.g1.v1 = Object.prototype.isPrototypeOf.call(p0, g1.a1);");
/*fuzzSeed-248247344*/count=990; tryItOut("\"use strict\"; v2 = evalcx(\"/* no regression tests found */\", g2.g2);");
/*fuzzSeed-248247344*/count=991; tryItOut("\"use strict\"; for (var v of this.i0) { try { print(uneval(e0)); } catch(e0) { } try { v0 = a1.length; } catch(e1) { } delete h1.keys; }");
/*fuzzSeed-248247344*/count=992; tryItOut("mathy2 = (function(x, y) { return Math.trunc(((Math.fround((y >>> 0)) >>> 0) ? ( + ((( ! Math.fround(Math.cbrt(x))) | 0) >= (Math.min(Math.sign((-1/0 | 0)), ( ! (( + (x | 0)) | 0))) >>> 0))) : ((mathy1((( + (( + ((Math.atan(x) >>> 0) >>> 0x080000000)) ? ( + (Math.asinh((Math.imul(y, Math.fround(2**53+2)) >>> 0)) >>> 0)) : ( + Math.atan2(( + -(2**53)), -0x100000001)))) | 0), (((((x | 0) != y) | 0) , ( + y)) >>> 0)) >>> 0) && y))); }); testMathyFunction(mathy2, [2**53+2, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Math.PI, 0x100000001, 1/0, 1, 0, -0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -(2**53), 0.000000000000001, -0x080000001, Number.MIN_VALUE, -0x080000000, 0x080000000, 42, 0x100000000, Number.MAX_VALUE, 2**53, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=993; tryItOut("testMathyFunction(mathy3, [-0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53+2), -0, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -Number.MIN_VALUE, -1/0, 0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 1, 0x100000001, 0x07fffffff, 0, -0x100000001, 1/0, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 0/0, 0.000000000000001, 0x100000000, 42, -0x100000000, Math.PI, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-248247344*/count=994; tryItOut("\"use strict\"; v2 = g2.t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-248247344*/count=995; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.acosh((mathy1((mathy1((Math.round(mathy0(y, ( + ( + Math.imul(( + x), ( + y)))))) | 0), Math.fround(( ~ Math.fround(y)))) | 0), ((((y | 0) + (Math.min(1, (x >= 1.7976931348623157e308)) | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[objectEmulatingUndefined(), [1], 0/0, new Boolean(false), [1], new Boolean(false), [1], objectEmulatingUndefined(), new Boolean(false), 0/0, 0/0, [1], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0/0, 0/0, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), [1], 0/0, [1], objectEmulatingUndefined(), 0/0, 0/0, [1], 0/0, new Boolean(false), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), [1], 0/0, [1], 0/0, [1], [1], [1], [1], [1], new Boolean(false), objectEmulatingUndefined(), [1], new Boolean(false), objectEmulatingUndefined(), 0/0, [1], objectEmulatingUndefined(), 0/0, new Boolean(false), [1], objectEmulatingUndefined(), [1], new Boolean(false), objectEmulatingUndefined(), 0/0, [1], new Boolean(false), new Boolean(false), new Boolean(false), [1], objectEmulatingUndefined(), 0/0, [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined()]); ");
/*fuzzSeed-248247344*/count=996; tryItOut("if(true) { if (((function fibonacci(vxvdki) { o2.o1 = new Object;; if (vxvdki <= 1) { ; return 1; } e2 = new Set;; return fibonacci(vxvdki - 1) + fibonacci(vxvdki - 2); print(x); })(2))) {(26); } else /*MXX2*/g2.Uint16Array.prototype.BYTES_PER_ELEMENT = e0;}");
/*fuzzSeed-248247344*/count=997; tryItOut("mathy5 = (function(x, y) { return mathy3(Math.sign(((( + (( + ( + Math.hypot(x, y))) >>> 0)) >>> 0) | 0)), ( + Math.log((((Math.hypot(y, Math.log1p(x)) >>> 0) | 0) * Math.imul(( - Math.sinh(x)), (( + Math.atan2((( ! (x >>> 0)) >>> 0), x)) % Math.fround(y))))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -(2**53), Math.PI, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 2**53+2, 1/0, -(2**53+2), -(2**53-2), 42, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 0x080000000, -0x07fffffff, 1, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 0x100000000, 2**53, -0x080000001, -0, 0.000000000000001, 0/0, 0x07fffffff, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=998; tryItOut("{var r0 = x | x; var r1 = r0 & x; print(x); var r2 = r0 + r0; var r3 = x % r0; var r4 = 9 * r2; var r5 = 8 | r4; var r6 = 8 * 2; print(r4); var r7 = r0 * r5; var r8 = r4 - 0; r6 = 7 - 4; var r9 = r5 | r8; var r10 = 9 * r8; var r11 = r9 - 1; var r12 = r5 / 9; print(r4); var r13 = 4 % r10; var r14 = r1 + r4; var r15 = 3 + 5; var r16 = 2 % r15; var r17 = r14 + r12; var r18 = r6 * r11; var r19 = r8 - x; var r20 = r13 - r18; var r21 = r12 ^ 6; r6 = r13 - 3; var r22 = 4 / 9; r5 = r6 % r3; r17 = r7 - 3; var r23 = 8 | r18; r13 = r16 - 1; var r24 = 3 | r1; r14 = 3 * r23; r7 = r9 / 3; var r25 = 1 & r14; var r26 = r24 ^ r17; var r27 = r25 * r22; var r28 = r4 % 9; r1 = 2 * r24; var r29 = r5 % r25; var r30 = r21 * r5; r13 = r6 ^ r6; var r31 = r17 - r24; r24 = r4 * r19; var r32 = r3 | r13; var r33 = 8 & 2; var r34 = r12 + r18; var r35 = r17 - 7; r7 = 5 & 3; var r36 = r24 & 5;  }");
/*fuzzSeed-248247344*/count=999; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( + Math.pow(Math.fround(Math.max(Math.sinh(x), 2**53+2)), Math.fround(Math.min(((( + y) | 0) >>> 0), (x >>> 0))))))); }); testMathyFunction(mathy2, [-0x07fffffff, 0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -1/0, 1.7976931348623157e308, 0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, -Number.MAX_VALUE, 1, -0x100000001, 2**53-2, -0x0ffffffff, -0x080000000, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, Math.PI, 1/0, 0x080000000, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-248247344*/count=1000; tryItOut("/*vLoop*/for (let jrugjn = 0; jrugjn < 15; ++jrugjn, [,,z1]) { let x = jrugjn; o2.a0 = arguments; } function x(b, {}, ...x) { return x } a2 = this.m2.get(h2);");
/*fuzzSeed-248247344*/count=1001; tryItOut("");
/*fuzzSeed-248247344*/count=1002; tryItOut("mathy2 = (function(x, y) { return Math.imul(Math.atan2(((Math.expm1(((y / 1) | 0)) >>> 0) >= Math.tan(( + ( + ( ! ( + ( ~ (( + x) << y)))))))), ( ~ (Math.cosh(x) >>> 0))), (Math.asinh((((((Math.fround((x ? x : (-Number.MAX_SAFE_INTEGER | 0))) >>> 0) - Math.imul(x, mathy0(y, 0x100000001))) >>> 0) <= Math.abs(y)) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Boolean(false),  /x/ , new Boolean(false),  /x/ ,  /x/ , new Boolean(false), new Number(1.5), new Boolean(false),  /x/ ,  /x/ , new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), new Number(1.5),  /x/ ,  /x/ , new Boolean(false),  /x/ ,  /x/ , new Boolean(false), new Number(1.5),  /x/ , new Boolean(false), new Boolean(false), new Boolean(false),  /x/ , new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false),  /x/ ,  /x/ , new Boolean(false),  /x/ ,  /x/ , new Boolean(false),  /x/ ,  /x/ , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5),  /x/ ,  /x/ ,  /x/ , new Number(1.5),  /x/ , new Boolean(false), new Number(1.5), new Boolean(false), new Number(1.5), new Boolean(false), new Number(1.5), new Number(1.5),  /x/ ,  /x/ ]); ");
/*fuzzSeed-248247344*/count=1003; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.sign((( + (( + Math.atan2(( ! x), (( ~ y) >>> 0))) & ( + Math.max((( ~ Math.fround(Math.atan2((y >>> 0), (Number.MAX_VALUE >>> 0)))) | 0), x)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1004; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot(((Math.min(( + ( ! Math.ceil(y))), x) >>> 0) < ( + x)), (Math.expm1(Math.fround((Math.fround(x) >> x))) != Math.fround(( ! y)))); }); testMathyFunction(mathy0, [1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 1.7976931348623157e308, -(2**53), 0, 0x100000000, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -Number.MIN_VALUE, 0x07fffffff, -0x080000001, 2**53-2, -0, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, -(2**53-2), -0x080000000, Number.MAX_VALUE, 42, 0x080000001, -0x100000000, -0x0ffffffff, -0x07fffffff, 0x080000000, -(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1005; tryItOut("\"use strict\"; for (var p in i0) { try { /*RXUB*/var r = r2; var s = this.s0; print(r.test(s)); print(r.lastIndex);  } catch(e0) { } try { v1 = g0.runOffThreadScript(); } catch(e1) { } ; }");
/*fuzzSeed-248247344*/count=1006; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.cos(mathy0(mathy0((Math.fround((((Math.pow(( + x), ( + x)) | 0) >>> 0) | (Math.round(( + mathy0(42, y))) >>> 0))) >>> (mathy0((y >>> 0), Math.fround(y)) | 0)), ((mathy0((x >>> 0), y) >>> 0) ^ Math.hypot(Math.fround((x % x)), (Math.cosh(x) >>> 0)))), Math.imul(Math.fround(Math.imul(mathy0(x, Math.fround(Math.acos((y | 0)))), -0x100000001)), Math.log(-0x100000001)))); }); ");
/*fuzzSeed-248247344*/count=1007; tryItOut("testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 0.000000000000001, 0, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 42, 2**53+2, 0/0, -0x080000000, 0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, -0x100000001, 0x100000000, 2**53, 1/0, Math.PI, 2**53-2, -0x080000001, -(2**53-2), -0x100000000, Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, 1, Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1008; tryItOut("a2.forEach((function() { a2.push(m1, d, a2); return p1; }));");
/*fuzzSeed-248247344*/count=1009; tryItOut("testMathyFunction(mathy5, /*MARR*/[Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1010; tryItOut("if((x % 4 == 2)) {a2[19]; } else {throw \"\\u6AB4\"; }");
/*fuzzSeed-248247344*/count=1011; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.atan2(Math.min(Math.fround((Math.fround(y) / Math.fround(x))), (y ? y : Math.fround(y))), (( + Math.fround(Math.abs(( + x)))) | 0)), ( + Math.pow(Math.fround(Math.cos(mathy0((Math.fround(Math.log2((x | 0))) >>> 0), (0x07fffffff >>> 0)))), Math.imul(Math.fround(Math.imul(y, ( ~ x))), Math.sign(Math.fround(x)))))); }); testMathyFunction(mathy1, /*MARR*/[(4277) &  /x/ ,  '\\0' , -Infinity,  '\\0' , new Number(1.5),  '\\0' , (4277) &  /x/ , (4277) &  /x/ , -Infinity, new Number(1.5), new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' , -Infinity,  '\\0' , new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5),  '\\0' , new Number(1.5), -Infinity, (4277) &  /x/ , -Infinity, new Number(1.5),  '\\0' , (4277) &  /x/ ,  '\\0' , (4277) &  /x/ , new Number(1.5),  '\\0' , (4277) &  /x/ , (4277) &  /x/ , new Number(1.5),  '\\0' ,  '\\0' ,  '\\0' , -Infinity, (4277) &  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, (4277) &  /x/ , (4277) &  /x/ , (4277) &  /x/ , (4277) &  /x/ , -Infinity, new Number(1.5),  '\\0' , -Infinity, -Infinity, (4277) &  /x/ ,  '\\0' , new Number(1.5), -Infinity, (4277) &  /x/ ,  '\\0' , new Number(1.5), (4277) &  /x/ ,  '\\0' ,  '\\0' , new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5), -Infinity, new Number(1.5), (4277) &  /x/ ,  '\\0' , (4277) &  /x/ ,  '\\0' ,  '\\0' ,  '\\0' ]); ");
/*fuzzSeed-248247344*/count=1012; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.pow(((Math.pow(Math.fround(( - x)), (Math.max(( + x), (y * (y | 0))) >>> 0)) ? ((Math.fround(Math.imul(Math.fround(y), Math.fround(Math.fround(( - y))))) ? ((Math.round(Math.fround(Math.min(Math.fround(y), Math.fround(x)))) >>> 0) >>> 0) : (((Math.pow(y, (x >>> 0)) >>> 0) != ( + x)) >>> 0)) >>> 0) : ( + ( + Math.clz32(( + ( ~ (Math.ceil(x) | 0))))))) >>> 0), ( + ( - ( + mathy1(Math.fround(x), Math.fround(x)))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -(2**53-2), 1, -(2**53), 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -(2**53+2), Number.MIN_VALUE, 0x100000001, 42, -Number.MIN_VALUE, -0x080000000, 0x080000001, -0x080000001, 0x0ffffffff, 2**53, -0, 0x07fffffff, 0/0, 0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, -1/0, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1013; tryItOut("\"use asm\"; print(true);s0 = Proxy.create(h1, s2);");
/*fuzzSeed-248247344*/count=1014; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ( ! Math.expm1((Math.fround(Math.cosh(Math.fround(Math.fround((Math.fround(mathy2(2**53+2, y)) === x))))) >>> 0))); }); testMathyFunction(mathy5, [-(2**53+2), 2**53+2, -0x080000000, -(2**53-2), -1/0, -Number.MIN_VALUE, 0x07fffffff, 42, -0, 1, -(2**53), -0x07fffffff, -0x0ffffffff, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, 0x080000000, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, 0x0ffffffff, 0]); ");
/*fuzzSeed-248247344*/count=1015; tryItOut("\"use strict\"; g0.m0 = new Map(o1);");
/*fuzzSeed-248247344*/count=1016; tryItOut("/*infloop*/M:for( /x/ ;  /x/ ; [,]) {g1.offThreadCompileScript(\"function f0(o0.p1) new RegExp(\\\"\\\\\\\\1|\\\\\\\\2|(?!$*)+?|(?!\\\\\\\\B)*?|[^]|^|[^][^](\\\\\\\\d){2,4}{3,}\\\", \\\"gi\\\")\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination:  \"\"  }));{} }");
/*fuzzSeed-248247344*/count=1017; tryItOut("\"use strict\"; \"\\u78D9\";\no2.v2 = g2.runOffThreadScript();\n");
/*fuzzSeed-248247344*/count=1018; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.max(Math.hypot(( + (( + ( + y)) & (Math.pow((( - x) | 0), (( + ( ! 1.7976931348623157e308)) | 0)) >>> 0))), ( + (Math.acosh(Math.fround((1/0 << -1/0))) | 0))), (( ~ Math.max(Math.exp(0x100000001), ( + (Number.MIN_SAFE_INTEGER >>> 0)))) ? (( + (( + (( + Math.fround(( ~ (Math.trunc(x) | 0)))) && ( + x))) && 0.000000000000001)) | 0) : (( + ( + ( + ( - Math.fround((Math.fround(Math.fround(Math.hypot(Math.fround((x > x)), ( + ( + 0.000000000000001))))) / Math.fround(Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) ^ Math.fround(Math.fround((y & Math.fround(y))))))))))))) | 0))); }); ");
/*fuzzSeed-248247344*/count=1019; tryItOut("\"use strict\"; print(x);function z(eval, \u3056, x, eval, {NaN: (__proto__)}, window = ((28)), w = ((yield x)), eval = x, window, eval, x = \"\\u9045\", eval, d, x, e = function(id) { return id }, x, \u3056, x, b =  \"\" , x, e = this, yield, x, x, e, a)x = Proxy.createFunction(({/*TOODEEP*/})( \"\" ), new Function)this.g0.h0 = {};");
/*fuzzSeed-248247344*/count=1020; tryItOut("(new RegExp(\"(?:(?=[])|(?!\\\\b|(?:\\u00ad)+))\\\\1*\", \"y\"));");
/*fuzzSeed-248247344*/count=1021; tryItOut("mathy0 = (function(x, y) { return Math.pow((Math.tanh((((Math.atan2((( + Math.min((x | 0), ( + x))) | 0), ((Math.fround(x) ? Math.fround(( + -0x080000000)) : Math.fround((((-0 | 0) ? (0x100000001 | 0) : (y | 0)) | 0))) | 0)) | 0) >> Math.cosh((x <= y))) | 0)) >>> 0), Math.expm1((( + (Math.log10(( ~ (Math.hypot(y, (Math.min((x | 0), (x | 0)) | 0)) >>> 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [/0/, '0', (new Number(0)), false, true, 0, objectEmulatingUndefined(), 1, null, (function(){return 0;}), NaN, (new Boolean(true)), [], (new Boolean(false)), '/0/', ({valueOf:function(){return '0';}}), '', undefined, -0, 0.1, (new Number(-0)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), [0], (new String('')), '\\0']); ");
/*fuzzSeed-248247344*/count=1022; tryItOut("\"use strict\"; /*MXX2*/g1.g1.g1.Object.prototype.valueOf = v0;");
/*fuzzSeed-248247344*/count=1023; tryItOut("v0 = a2.length;");
/*fuzzSeed-248247344*/count=1024; tryItOut("mathy0 = (function(x, y) { return ( ! Math.cbrt(Math.imul((x * y), (( + (Math.ceil(Math.fround(-(2**53))) >>> 0)) | 0)))); }); testMathyFunction(mathy0, [-0x080000000, 0x080000001, 0/0, 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000000, -0, -Number.MIN_VALUE, -0x0ffffffff, 1, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 42, 0.000000000000001, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), -0x07fffffff, 0, Math.PI, -0x100000001, 1/0, Number.MAX_VALUE, -1/0, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1025; tryItOut("\"use strict\"; a1[2] = yield ( \"\" )({});");
/*fuzzSeed-248247344*/count=1026; tryItOut("/*RXUB*/var r = 8; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1027; tryItOut("\"use strict\"; if(false) { if (/\\1/y) {print(x);Array.prototype.forEach.call(a0, new Function); }} else {/*MXX1*/var o0 = g0.g2.Float32Array.prototype.BYTES_PER_ELEMENT;print(x); }");
/*fuzzSeed-248247344*/count=1028; tryItOut("e1.add(t1);a2 + v2;");
/*fuzzSeed-248247344*/count=1029; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ! ( + ( + (( - (x >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [0x0ffffffff, -0x100000001, Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, 42, -(2**53), -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, 1/0, 1, 1.7976931348623157e308, -0x080000000, 0x100000001, 2**53-2, -0x07fffffff, 0, 0x080000001, -0, -0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 0x07fffffff, Math.PI, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-248247344*/count=1030; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + Math.cbrt((Math.atan2(0, Math.atan2(\"\\u1415\", (Math.imul((y | 0), (Math.tan(2**53) | 0)) | 0))) ? Math.atan2((( ~ y) >>> 0), (( - (y | 0)) | 0)) : (((( ! (Math.fround(x) !== Math.fround(-0))) | 0) !== (x | 0)) | 0)))) ? ( + Math.imul(Math.fround((( ~ (( + ( ! ( + y))) | 0)) | 0)), Math.log((((x | 0) !== ( + (((-Number.MIN_VALUE | 0) ** (x | 0)) | 0))) | 0)))) : ( + Math.hypot(Math.min(y, (y == Math.fround(( + (Math.max((y >>> 0), (x >>> 0)) >>> 0))))), Math.fround(Math.atan2(Math.fround(Number.MIN_VALUE), Math.fround(( + ( - Math.exp(x)))))))))); }); ");
/*fuzzSeed-248247344*/count=1031; tryItOut("/*ADP-1*/Object.defineProperty(a1, ({valueOf: function() { e2.has(s2);return 8; }}), ({configurable: true}));");
/*fuzzSeed-248247344*/count=1032; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, [0.000000000000001, 42, -(2**53), -1/0, -0x100000000, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 0, -0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, 2**53+2, 2**53-2, -(2**53-2), Number.MAX_VALUE, 1, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 1/0, -0x100000001, 0x0ffffffff, 0x100000000, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1033; tryItOut("mathy4 = (function(x, y) { return Math.min((( ! (Math.fround(Math.hypot(mathy1(Math.atan2(x, (Math.imul((0/0 >>> 0), y) >>> 0)), mathy3(( + x), 0x080000001)), y)) >>> 0)) >>> 0), ( + ((( + Math.cos(x)) != y) === ( + Math.fround(Math.imul(Math.fround(Math.fround(mathy1((Math.log10(y) | 0), Math.fround(Math.abs(x))))), Math.fround((( ! ( + Math.min(( + Math.atan2(x, (x ? x : 2**53+2))), ( + 2**53+2)))) | 0)))))))); }); testMathyFunction(mathy4, /*MARR*/[undefined, undefined, NaN, NaN, NaN, undefined, undefined, NaN, NaN, NaN, undefined, NaN, NaN, undefined, undefined, undefined, NaN, NaN, undefined, undefined, NaN, undefined, undefined, undefined, undefined]); ");
/*fuzzSeed-248247344*/count=1034; tryItOut("L:with((void options('strict_mode'))){a2.unshift(p1, m0, o0.p1, v1, h2, m1);m1.delete(e0); }");
/*fuzzSeed-248247344*/count=1035; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"yi\"); var s = \"_\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1036; tryItOut("");
/*fuzzSeed-248247344*/count=1037; tryItOut("let (y, setuhe, x = -12, jqijop, wqlqjt, qutnvm, c, \u3056, oywvbz, c) { v0 = Object.prototype.isPrototypeOf.call(f2, g2.p2); }");
/*fuzzSeed-248247344*/count=1038; tryItOut("this.a2 + i2;");
/*fuzzSeed-248247344*/count=1039; tryItOut("/*RXUB*/var r = /(\\3(?![^])|[\udc55\\\u291b]{4})|\\2(?=(?:[\\s\\cE-\\u5396\u0008-\\u004f]{1048575,1048578})){8589934592}/gyim; var s = \"\\ueb7a\\u00f0\\n\\u00f0\"; print(s.replace(r, decodeURIComponent)); ");
/*fuzzSeed-248247344*/count=1040; tryItOut("\"use strict\"; /*RXUB*/var r = /((?!\\D){3,})/im; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=1041; tryItOut("mathy4 = (function(x, y) { return ( ! mathy2(Math.fround(Math.imul(Math.atan2((1.7976931348623157e308 | 0), Math.fround(x)), ( - Math.fround(Math.asin(( + y)))))), ( + Math.log10(-0x100000000)))); }); testMathyFunction(mathy4, [-0x07fffffff, Number.MAX_VALUE, -0x080000000, 2**53+2, 0x100000001, 42, -0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, 0x0ffffffff, -(2**53+2), 0x080000001, Number.MIN_SAFE_INTEGER, 1, -(2**53-2), Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, 0x07fffffff, 2**53, -(2**53), -0x100000000, Number.MIN_VALUE, 2**53-2, 0/0, -0x100000001, -Number.MIN_VALUE, 0x080000000, -1/0, 0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1042; tryItOut("\"use asm\"; return  /x/ ;c = Math.trunc( /x/g );\nyield;for (var p in o1.v0) { try { this.a2.push(b2, (Math.hypot(x, (4277)))); } catch(e0) { } try { o1.e2.has(f2); } catch(e1) { } print(uneval(g0)); }\n");
/*fuzzSeed-248247344*/count=1043; tryItOut("mathy1 = (function(x, y) { return Math.sqrt((((( + ( + mathy0(mathy0(Math.imul(y, x), y), ((( + Math.expm1(0x07fffffff)) != y) | 0)))) >>> 0) !== (Math.pow(( + Math.log2(x)), 0x100000000) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0, -0x080000001, 1.7976931348623157e308, 0x100000001, 1, -0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, -0x0ffffffff, -(2**53+2), -(2**53-2), 0/0, 0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, 0x080000001, -Number.MAX_VALUE, 2**53-2, Math.PI, 0x07fffffff, 42, -Number.MIN_VALUE, -(2**53), 0x080000000, 0x100000000, -1/0, 2**53, 2**53+2, -0x100000000]); ");
/*fuzzSeed-248247344*/count=1044; tryItOut("/*vLoop*/for (var ddgxck = 0; ddgxck < 143; ++ddgxck, (4277).eval(\"/* no regression tests found */\")) { y = ddgxck; for (var p in b1) { try { v2 = Object.prototype.isPrototypeOf.call(t0, i0); } catch(e0) { } v2 = Array.prototype.reduce, reduceRight.call(o1.a1, (function mcc_() { var ghxynj = 0; return function() { ++ghxynj; if (/*ICCD*/ghxynj % 7 == 4) { dumpln('hit!'); try { let v0 = evalcx(\"26\", o0.g2); } catch(e0) { } try { a0 = []; } catch(e1) { } try { v1 + ''; } catch(e2) { } b2 = new SharedArrayBuffer(144); } else { dumpln('miss!'); try { v0 = b0.byteLength; } catch(e0) { } v1 = g1.eval(\"function f0(o1.v2)  { return window } \"); } };})(), o0, new (x)( /x/g ), h0, p2); } } ");
/*fuzzSeed-248247344*/count=1045; tryItOut("do s2 += 'x'; while(((Math.min(-0.493, 6))) && 0);");
/*fuzzSeed-248247344*/count=1046; tryItOut("mathy2 = (function(x, y) { return (Math.sign(Math.log2(Math.hypot(Math.fround(Math.fround(( + Math.fround(y)))), 42))) < Math.atan2(Math.atan2((( + mathy1(y, ( + Math.min(x, y)))) | 0), ( + mathy0((-(2**53) >>> 0), ( + x)))), ( - ((y > 1) | 0)))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, 1.7976931348623157e308, Math.PI, -1/0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, Number.MAX_VALUE, 0x080000001, 0x080000000, 0x0ffffffff, 0x100000000, Number.MIN_VALUE, -0x080000001, -0x080000000, 42, 2**53, 2**53-2, 2**53+2, -0x100000001, 0, 0x100000001, 0x07fffffff, 0.000000000000001, 1, -0, -(2**53+2), -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1047; tryItOut("switch(\"\\u7F20\".watch(\"normalize\", offThreadCompileScript)) { case  /x/g : o0.t2 = new Int32Array(3);break; case 7: default: break; /*vLoop*/for (ljvuvj = 0; ljvuvj < 16; ++ljvuvj) { let d = ljvuvj; print(d); } break;  }");
/*fuzzSeed-248247344*/count=1048; tryItOut("var x = d = Proxy.createFunction(({/*TOODEEP*/})(({a2:z2})), /*wrap1*/(function(){ g0.e0 + '';return new RegExp(\".\", \"y\")})()), d = x, x = x, guavlm, \u3056, w = x, mygcpy, w = x;/*infloop*/L:for(arguments++; -19; WeakMap( \"\" )) {m2.set(o1.a1, h1);this.b2 + p2; }");
/*fuzzSeed-248247344*/count=1049; tryItOut(";");
/*fuzzSeed-248247344*/count=1050; tryItOut("(new RegExp(\"$|$|(?=^)+*|(?!(?:(?:$|\\ufcc5)))|(.){4}\", \"yi\"));");
/*fuzzSeed-248247344*/count=1051; tryItOut("mathy2 = (function(x, y) { return (Math.fround((Math.fround(( + ( ~ ( + x)))) | Math.fround(mathy1((( ~ 0x0ffffffff) ^ ( + mathy1(y, mathy1(y, (y | 0))))), ((Math.imul((x >>> 0), mathy1(x, (( ~ Math.fround(Math.fround((y < x)))) >>> 0))) | 0) | 0))))) <= ( + Math.max(( + let ( /x/ ) 20), Math.max(((mathy0(2**53-2, y) | 0) + (Math.sign(( + (y | 0))) | 0)), ( ! (y | (Math.log2((y | 0)) | 0))))))); }); testMathyFunction(mathy2, [-(2**53-2), 0x080000000, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 1, 0x07fffffff, -(2**53), 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, 1.7976931348623157e308, 0x080000001, 42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0, 0, -1/0, -0, -Number.MAX_VALUE, -0x100000000, 2**53, -0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0x0ffffffff, 2**53+2, 1/0, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1052; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-248247344*/count=1053; tryItOut("mathy2 = (function(x, y) { return (( - ((( + Math.min(Math.fround(( + Math.max(( + (Math.min((x | 0), (Math.hypot(y, y) | 0)) | 0)), ( + ( + mathy1(y, y)))))), (Math.max(( - ((( ~ x) >>> 0) >>> 0)), 0/0) >>> 0))) , Math.tan((( + (( + ((0/0 | 0) > (y | 0))) > Math.hypot(y, Math.fround(Math.max((x >>> 0), ( + y)))))) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1054; tryItOut("Object.defineProperty(this, \"f2\", { configurable: true, enumerable: (x % 2 == 1),  get: function() {  return Proxy.createFunction(h0, o2.f2, g0.f0); } });");
/*fuzzSeed-248247344*/count=1055; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(Math.hypot(((Math.sin((Math.fround(Math.pow(y, y)) >>> 0)) | 0) !== ( ! Math.max(Math.log(x), Math.imul(x, x)))), ( ~ Math.log((y / y)))), ( - ( + ( + Math.fround(Math.expm1(x)))))); }); testMathyFunction(mathy0, [-0x07fffffff, 1, -0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, -(2**53+2), -0x100000000, 0/0, 2**53-2, 42, 1.7976931348623157e308, 0x080000001, Number.MAX_VALUE, 2**53, 0x080000000, 0x07fffffff, Number.MIN_VALUE, 0x100000000, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), 0.000000000000001, -0x0ffffffff, 0x0ffffffff, -1/0]); ");
/*fuzzSeed-248247344*/count=1056; tryItOut("\"use strict\"; h0 = ({getOwnPropertyDescriptor: function(name) { m2.toString = (function(a0, a1, a2, a3, a4) { var r0 = a4 % a2; var r1 = x | a1; var r2 = r1 ^ a3; var r3 = 5 & r2; var r4 = 1 | a2; a1 = r0 / a1; a3 = 5 & a3; var r5 = x | r3; var r6 = a1 - 1; var r7 = x % r6; var r8 = r1 | x; var r9 = a0 - 9; r1 = 7 & 4; var r10 = x * r6; var r11 = 1 & r7; var r12 = 1 | r0; r11 = r3 & 2; r7 = a0 % 4; var r13 = r12 + 4; var r14 = 9 + r2; r3 = r10 ^ a3; var r15 = r12 % r0; var r16 = r10 + x; var r17 = r10 | a1; a2 = r5 | r15; print(a1); var r18 = a0 % 2; var r19 = a3 & r18; r12 = r1 * r16; a2 = 5 - 3; var r20 = r14 / r4; print(a3); print(r11); r8 = r16 & a3; a2 = 4 * r4; var r21 = r19 ^ 3; var r22 = r12 / r17; r3 = r1 - 0; var r23 = r14 & r17; var r24 = 2 * 1; var r25 = 7 * 4; var r26 = 0 + r6; var r27 = r3 % 1; var r28 = r24 % 1; var r29 = 7 ^ r4; r25 = r15 ^ 6; var r30 = r20 | r11; return x; });; var desc = Object.getOwnPropertyDescriptor(h2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*MXX3*/g0.ReferenceError = g1.ReferenceError;; var desc = Object.getPropertyDescriptor(h2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw b2; Object.defineProperty(h2, name, desc); }, getOwnPropertyNames: function() { print(f2);; return Object.getOwnPropertyNames(h2); }, delete: function(name) { this.v1 = evaluate(\"/* no regression tests found */\", ({ global: g0.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 0), noScriptRval: (x % 8 == 6), sourceIsLazy: x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: Array.prototype.some, delete: function() { return true; }, fix: function() { return []; }, has: undefined, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: /*wrap1*/(function(){ /*RXUB*/var r = r2; var s = this.s1; print(s.search(r)); return encodeURIComponent})(), enumerate: ('fafafa'.replace(/a/g, Promise.reject)), keys: function() { return []; }, }; })(Math.atan(-13)), function(y) { return (((( + ( ~ ( + (Math.fround(Math.fround(-0x0ffffffff)) | 0)))) >>> 0) + ((( ! (-0x100000001 | (y <= ( + y)))) !== (Math.atan2(Math.fround(Math.log10(y)), x) ^ Math.fround(x))) >>> 0)) >>> 0) }), catchTermination: true }));; return delete h2[name]; }, fix: function() { v2.toSource = (function() { t1[v2] = p2; return s2; });; if (Object.isFrozen(h2)) { return Object.getOwnProperties(h2); } }, has: function(name) { /*RXUB*/var r = /[\\0-\\u29AE\uc349]+(?!(?:(([]))(?=(?!(?=\\W)))[^]\\s+?|\\S[^])*?)/g; var s = \"\\u2029\\u2029\\u29ae\\u29ae\\u29ae\\u29ae\\u9a07\\n_\\u9a07\\n_\"; print(r.test(s)); ; return name in h2; }, hasOwn: function(name) { t0 = x;; return Object.prototype.hasOwnProperty.call(h2, name); }, get: function(receiver, name) { b2 + this.f1;; return h2[name]; }, set: function(receiver, name, val) { g0.s0 = '';; h2[name] = val; return true; }, iterate: function() { v1.toSource = delete z.x;; return (function() { for (var name in h2) { yield name; } })(); }, enumerate: function() { delete h2.getOwnPropertyNames;; var result = []; for (var name in h2) { result.push(name); }; return result; }, keys: function() { return t0; return Object.keys(h2); } });");
/*fuzzSeed-248247344*/count=1057; tryItOut("Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-248247344*/count=1058; tryItOut("mathy5 = (function(x, y) { return (Math.imul(((((( + (mathy3(( - -0x100000000), (((((x <= ( + Math.min(( + 0/0), ( + x)))) >>> 0) != (( + mathy0(y, y)) >>> 0)) >>> 0) >>> 0)) >>> 0)) <= (Math.fround(Math.atan(Math.fround(x))) >>> 0)) >>> 0) / ( + ( ! ( + Math.atan2(y, -0x080000001))))) | 0), ( ~ (Math.imul((Math.log2(Math.fround(x)) >>> 0), (Math.min(Math.fround(Math.fround(Math.sqrt(0x080000000))), x) >>> 0)) == 2**53+2))) | 0); }); ");
/*fuzzSeed-248247344*/count=1059; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-(2**53), 0.000000000000001, 2**53+2, 42, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, 1, Number.MAX_VALUE, 0/0, 0x0ffffffff, 0x100000000, 0x080000001, -0, 2**53, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, 0x080000000, -0x100000001, -0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, 0, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1060; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = (((((-0x8000000) ? ((i1) ? (i1) : (0x2c48ca7e)) : ((((0x3cfa9472)-(0xf89e188f))>>>(-0xfffff*(0xa1d04988)))))) | ((0xac0dc8c9)+((~~(+(imul((0xe725d338), (0x471bdfd7))|0))) != (~((i1)))))));\n    }\n    i1 = (-0x8000000);\n    return +((-2305843009213694000.0));\n  }\n  return f; })(this, {ff: (function(x, y) { return -Number.MIN_SAFE_INTEGER; })}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=1061; tryItOut("mathy5 = (function(x, y) { return ( + (( + ((Math.hypot((( + Math.sinh(y)) | 0), (( + (( + ( ~ x)) ? ( + -0x100000000) : ( + Math.hypot(x, x)))) | 0)) | 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=1062; tryItOut("h0.keys = (function(j) { if (j) { try { o1.v2 = Object.prototype.isPrototypeOf.call(p0, s2); } catch(e0) { } try { m2.has(b0); } catch(e1) { } try { o0 + g1; } catch(e2) { } /*ODP-1*/Object.defineProperty(b0, \"__parent__\", ({get: Array.prototype.findIndex, set: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(){}, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function(y) { \"use strict\"; yield y; print(\u3056 |= z);; yield y; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: /*wrap2*/(function(){ \"use strict\"; var exnsom = 15; var wybdvz = mathy0; return wybdvz;})(), }; }), enumerable: false})); } else { Array.prototype.sort.call(a1, Date.prototype.valueOf.bind(o2), e1, g0); } });");
/*fuzzSeed-248247344*/count=1063; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.min(((((( + Math.atan2(( + x), ( + (Math.fround(Math.round(42)) ^ ( + x))))) < ( + (( - ( + x)) - ( + 0x080000000)))) ? (( ! (( ~ Math.fround((y & -Number.MIN_VALUE))) | 0)) >>> 0) : mathy0(x, y)) | 0) | 0), mathy2(Math.imul((((mathy1((( + -0x07fffffff) || ( + x)), Math.log2(x)) | 0) > ( + ((Math.fround(( + ((( + Math.atanh(( + x))) >>> 0) ^ ((-Number.MAX_VALUE >> y) | 0)))) | (( + Math.round(( + 0.000000000000001))) >>> 0)) >>> 0))) | 0), y), (0x080000001 - Math.atan2(x, Math.log2(y))))) | 0); }); testMathyFunction(mathy4, [0/0, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x080000001, -(2**53+2), 0.000000000000001, -0x080000001, 2**53+2, -0, 0x100000001, 42, 0x080000000, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, -1/0, Number.MAX_VALUE, Math.PI, -(2**53), Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, 1, 0x07fffffff, -0x100000001, -(2**53-2), -Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-248247344*/count=1064; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1065; tryItOut(";");
/*fuzzSeed-248247344*/count=1066; tryItOut("\"use strict\"; /*iii*//*infloop*/for({y: {}} = x; false; (new Boolean(false))) /* no regression tests found *//*hhh*/function uewruq(\u3056, x, ...x){e0.add(this.g0);}\no1 = {};\n");
/*fuzzSeed-248247344*/count=1067; tryItOut("\"use strict\"; this.s0 += o1.s0;");
/*fuzzSeed-248247344*/count=1068; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.ceil(Math.fround(Math.round(mathy2(Math.fround(Math.trunc((x <= Math.pow((x | 0), 0x0ffffffff)))), mathy2(( + x), x))))); }); testMathyFunction(mathy4, [-0x100000001, 0/0, 2**53+2, -(2**53), Math.PI, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 1, 0x100000001, Number.MIN_VALUE, -0x080000000, 2**53, 0x100000000, 0x080000001, 1.7976931348623157e308, -1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -(2**53+2), 42, Number.MAX_VALUE, 0x07fffffff, 1/0, 0, -0x100000000, 0x080000000, -0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1069; tryItOut("testMathyFunction(mathy1, /*MARR*/[false, false, objectEmulatingUndefined(), (1/0), false, NaN,  /x/g , false, (1/0), objectEmulatingUndefined(), false,  /x/g ,  /x/g ,  /x/g , false, NaN, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), NaN, NaN, NaN, objectEmulatingUndefined(), false, false, false, false, false, false, NaN, objectEmulatingUndefined(), (1/0), false, NaN, (1/0), (1/0), false, false, false, (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN,  /x/g , objectEmulatingUndefined(), false, NaN,  /x/g , false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, false, objectEmulatingUndefined(), NaN, false, false, false, (1/0), false,  /x/g , NaN, (1/0), (1/0), NaN, (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(),  /x/g , (1/0),  /x/g , false, NaN, false, false,  /x/g ,  /x/g , (1/0), NaN, (1/0), NaN, false, NaN, objectEmulatingUndefined(),  /x/g , false,  /x/g ,  /x/g , (1/0), false, (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, (1/0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), NaN, false, (1/0), objectEmulatingUndefined(), NaN,  /x/g , objectEmulatingUndefined(), (1/0), false,  /x/g , objectEmulatingUndefined(), false, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), false, (1/0),  /x/g , NaN, NaN, false, objectEmulatingUndefined(), objectEmulatingUndefined(), NaN]); ");
/*fuzzSeed-248247344*/count=1070; tryItOut("{ void 0; void relazifyFunctions('compartment'); }");
/*fuzzSeed-248247344*/count=1071; tryItOut("(Object.defineProperty(y, \"sub\", ({set: (\u3056--).toString, enumerable: false})));");
/*fuzzSeed-248247344*/count=1072; tryItOut("print((4277));");
/*fuzzSeed-248247344*/count=1073; tryItOut("v1 = false;");
/*fuzzSeed-248247344*/count=1074; tryItOut("\"use strict\"; for (var p in f1) { (void schedulegc(g0)); }");
/*fuzzSeed-248247344*/count=1075; tryItOut("/*hhh*/function efagnf([{x: NaN, a, z: []}, , , , w], this.z, x, e, b = (4277), eval, __count__, b = (({NaN: undefined})), c, x, x, \u3056, x, w, x, x =  /x/ , a = \"\\u36A2\", NaN, x = 9, e, x, NaN, x =  '' , a, b, x =  /x/g , x, x = false, window, eval, z, z = window, c, NaN, x, e, z, y, x, x = \"\\uBE3D\", \"8\", y =  /x/ , \u3056, x, x, x, NaN, x, x, y, x, e = ({a1:1}), x =  /x/g , x, x =  '' , c, a, x, z = false, NaN, d, c, x, w, 2 = window, x, e, c, x, y = /\\2\\W|\\d**?|(?=(?=\\d|\\S))|\\2\\b\\b|(?=((?=(?=^))+?))(?!\\1)/gim, a = null, z, x, x, \u3056 = this, NaN =  \"\" , w){this.v2 = 0;}/*iii*//*infloop*/while((efagnf) =  '' )print((4277));");
/*fuzzSeed-248247344*/count=1076; tryItOut("\"use strict\"; e2 = new Set;");
/*fuzzSeed-248247344*/count=1077; tryItOut("");
/*fuzzSeed-248247344*/count=1078; tryItOut("\"use strict\"; Object.freeze(s0);");
/*fuzzSeed-248247344*/count=1079; tryItOut("f0.__proto__ = o2.p1;");
/*fuzzSeed-248247344*/count=1080; tryItOut("/*MXX1*/const this.o1 = this.g2.Object.prototype.__lookupSetter__;");
/*fuzzSeed-248247344*/count=1081; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0, 0x080000000, 0.000000000000001, -1/0, 0x100000000, -Number.MAX_VALUE, -0x080000001, -0x100000001, 2**53, 1/0, 0/0, 0x100000001, -(2**53-2), -0x100000000, -(2**53), 1.7976931348623157e308, 0x080000001, 0x0ffffffff, -0x07fffffff, -(2**53+2), 42, Number.MAX_VALUE, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53+2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1082; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (2199023255553.0);\n    {\n      d1 = (d1);\n    }\n    i0 = (i0);\n    return (((0x99105003)+(0xf90e34c6)))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0/0, 0.000000000000001, 0x080000000, -(2**53+2), 1/0, -0, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, 0x07fffffff, 2**53-2, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -(2**53-2), 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0, -(2**53), 42, -0x100000001, Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, 2**53, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1083; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1084; tryItOut("(/*FARR*/[[z1], ].filter(function (x) { function(y) { yield y; print(x);; yield y; } } , /(?=(?!(.?[^])))/gm))(x), y = ( '' )(-8), d = -2, pqcsww, ucaody, drvsra, eval, rewsgh;f1.__iterator__ = (function() { for (var j=0;j<156;++j) { f1(j%2==1); } });");
/*fuzzSeed-248247344*/count=1085; tryItOut("g2.e1 = new Set(v0);");
/*fuzzSeed-248247344*/count=1086; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, -0x100000000, -0x080000000, -0, 2**53+2, 0/0, 1, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, 0x080000000, -1/0, 0, 1/0, 2**53-2, -(2**53), 42, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 0x07fffffff, 2**53, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, -Number.MAX_VALUE, 0x100000001, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1087; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy0(( + (Math.fround(mathy1(Math.fround((Math.atan2(Math.fround(Math.hypot(Math.fround(y), -0x0ffffffff)), x) | 0)), Math.fround(( + (( + ( ~ y)) << ( + -0x100000000)))))) - (y !== Math.fround((Math.fround(( ~ y)) > y))))), ((mathy1((y | 0), (( - (x >>> 0)) >>> 0)) | 0) <= Math.min((Math.min(( + ( - (Math.min(y, Math.fround(-0x100000001)) | 0))), ( + (Math.clz32(y) | 0))) | 0), ((Math.fround(y) === x) != ( + -(2**53))))))); }); testMathyFunction(mathy2, [0x07fffffff, Number.MIN_VALUE, -0x100000000, 0x080000000, 42, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -(2**53), 0x100000000, 0x100000001, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0x080000001, 1/0, 1.7976931348623157e308, -0x100000001, 0/0, 0, -0, -Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, -0x07fffffff, -(2**53+2), 1, -1/0, Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=1088; tryItOut("\"use strict\"; x.name;");
/*fuzzSeed-248247344*/count=1089; tryItOut("for (var p in v0) { try { print(uneval(f0)); } catch(e0) { } try { print(uneval(i1)); } catch(e1) { } try { m2.get(b0); } catch(e2) { } v1 = evaluate(\"[[]]\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval:  \"\" , sourceIsLazy: false, catchTermination: true })); }");
/*fuzzSeed-248247344*/count=1090; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1091; tryItOut("\"use strict\"; a2.reverse();");
/*fuzzSeed-248247344*/count=1092; tryItOut("mathy1 = (function(x, y) { return Math.asin(( ! ( ~ ( - (Math.fround(Math.sin((y | 0))) <= ( ~ x)))))); }); testMathyFunction(mathy1, [2**53-2, 0x0ffffffff, -(2**53), 2**53, Number.MAX_VALUE, 1, -0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, 0, -1/0, Math.PI, -0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, 2**53+2, 0.000000000000001, 1.7976931348623157e308, 0x080000001, Number.MIN_VALUE, -0, 0x100000001, 42, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, -0x080000000, -(2**53+2), 0x080000000, -Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1093; tryItOut("s1 += s1;");
/*fuzzSeed-248247344*/count=1094; tryItOut("a2.push(a1, o2, o0);");
/*fuzzSeed-248247344*/count=1095; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.cosh((x !== x)), (Math.expm1(( + Math.fround(mathy0((Math.atan2(x, x) | 0), y)))) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=1096; tryItOut("\"use asm\"; s0 + a0\n/*RXUB*/var r = /(?!(?![^]|[^]{4,}))/i; var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=1097; tryItOut("print(new (DataView.prototype.getUint16)(/*FARR*/[]));");
/*fuzzSeed-248247344*/count=1098; tryItOut("e0 + '';");
/*fuzzSeed-248247344*/count=1099; tryItOut("\"use asm\"; break ;function y(x) { yield /(?=\\s{4}(?=\\B+))/gyi } i1 = new Iterator(s0, true);");
/*fuzzSeed-248247344*/count=1100; tryItOut("m1.has(b1);");
/*fuzzSeed-248247344*/count=1101; tryItOut("mathy4 = (function(x, y) { return (Math.fround(mathy2(( + ( ~ ( + ( + Math.sinh(((Math.max((y | 0), x) | 0) >>> 0)))))), Math.cosh(y))) ? Math.fround(Math.fround(Math.atan(Math.pow((((Math.fround(( ! Math.fround(Number.MIN_SAFE_INTEGER))) | 0) ** (Math.fround((0x07fffffff >> Math.fround(y))) | 0)) | 0), (Math.sin((y >>> 0)) >>> 0))))) : (Math.atan2(Math.max(x, (y >>> 0)), ((Math.atan2(((Math.fround((Math.fround(x) >= Math.fround(x))) / (-Number.MIN_VALUE ? -(2**53) : y)) >>> 0), (y >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[-0x0ffffffff, -0x0ffffffff, -0x0ffffffff, null, -0x0ffffffff, -0x0ffffffff, new String(''), null, new String(''), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, new String('')]); ");
/*fuzzSeed-248247344*/count=1102; tryItOut("v0 = g2.eval(\"g1.s0 += s2;\");");
/*fuzzSeed-248247344*/count=1103; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Uint32ArrayView[(((((Uint16ArrayView[((0xf8945d3a)) >> 1]))>>>(-(0x7a0c43f1))))) >> 2]) = (((((i0)-(!((~((i0)))))) << ((/*FFI*/ff(((0x1fbdefd8)))|0)+(i0))))-((i0) ? ((0x477c30a0) ? (0xf801a446) : (0xc2509829)) : (i0))-(i0));\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var fwzqcv = function(y) { yield y; g1.v2 = (s2 instanceof b0);; yield y; }.prototype; var llcvrl = EvalError.prototype.toString; return llcvrl;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0.1, [], /0/, 1, (new Boolean(true)), undefined, ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Number(-0)), -0, '/0/', ({valueOf:function(){return 0;}}), 0, '\\0', '', null, true, NaN, objectEmulatingUndefined(), (new String('')), '0', ({toString:function(){return '0';}}), false, [0], (new Number(0)), (function(){return 0;})]); ");
/*fuzzSeed-248247344*/count=1104; tryItOut("this.p0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    (Float64ArrayView[1]) = ((-7.737125245533627e+25));\n    i2 = (i3);\n    (Uint8ArrayView[1]) = ((0xef4a854));\n    d0 = (Infinity);\n    {\n      i2 = (i2);\n    }\n    (Float64ArrayView[((i2)) >> 3]) = ((d1));\n    return (((0xf716fe)-(/*FFI*/ff()|0)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return ((( - Math.log1p((( ! (( + Math.pow(y, ( ~ (2**53+2 >>> 0)))) | 0)) | 0))) >>> (( + ((Math.asin((Math.hypot(Math.fround((((Math.fround(Math.hypot((( + x) * x), Math.fround((Math.cos((Math.abs(Math.fround(x)) >>> 0)) >>> 0)))) | 0) ? (( + ( ~ Math.min(x, Math.log(-0x080000000)))) | 0) : (Math.hypot((((((Math.min((y >>> 0), (x >>> 0)) >>> 0) | 0) ** (Math.sqrt(Math.fround(( - Math.fround(-Number.MIN_VALUE)))) | 0)) | 0) >>> 0), (Math.hypot(Math.fround(x), -(2**53)) >>> 0)) | 0)) | 0)), Math.clz32((((Math.fround((( + y) % ( + 1/0))) >>> 0) != ((( + Math.fround((Math.fround(Math.atan2(x, 0)) && (Math.max(2**53, (-0x0ffffffff >>> 0)) | 0)))) >= ( + Math.fround((Math.fround(Math.imul(x, x)) ? Math.fround(x) : y)))) >>> 0)) >>> 0))) | 0)) | 0) >> ( + ((( ~ (Number.MIN_SAFE_INTEGER >>> 0)) ? Math.min(( ~ y), Math.fround(Math.atan2(-0x100000000, Math.acos(x)))) : Math.fround(Math.hypot(( + (-1/0 ? (Math.min(x, x) >>> 0) : Math.exp(( ! x)))), ( + Math.max(Math.fround(Math.fround(Math.trunc(x))), Math.log(0x100000001)))))) * ( - Math.pow(Math.max((y | 0), Math.fround((y ? x : Math.fround(-Number.MIN_SAFE_INTEGER)))), Math.min(y, ( + x)))))))) | 0)) === (( ~ (( + ( + Math.fround(Math.imul(Math.fround(Math.acosh((((( - (y >>> 0)) | 0) > Math.cbrt(x)) ? (((Math.fround(y) >>> 0) % (Math.min(y, (0x100000000 | 0)) >>> 0)) >>> 0) : x))), ( + ((Math.hypot(x, (((-0x080000001 & Math.fround(x)) | 0) | 0)) >> ((( + ((x & y) | 0)) >>> 0) >>> 0)) >>> 0)))))) >>> 0)) >>> 0)); })}, new SharedArrayBuffer(4096));");
/*fuzzSeed-248247344*/count=1105; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( + (Math.trunc((Math.fround(Math.fround(Math.cosh(Math.fround((Math.hypot(y, ( ! Number.MIN_VALUE)) + 0x080000000))))) / Math.fround((x !== 0x100000001)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1106; tryItOut("/*RXUB*/var r = /(?!\\3)|$(?=[\\n\u00df-\\u8171])\\3|\\1[:-\\u005d\\w\\/](\\1+)+?\\2?[^\\w\\s]+*/im; var s = \"\"; print(s.replace(r, s, \"\")); ");
/*fuzzSeed-248247344*/count=1107; tryItOut("mathy3 = (function(x, y) { return (Math.pow(Math.fround(Math.pow(((Number.MAX_SAFE_INTEGER < x) | 0), Math.fround(Math.fround(Math.sinh(mathy2(( + (( + y) ? ( + (-(2**53+2) - x)) : y)), 1)))))), ( + Math.expm1(Math.atan2(Math.asin(( + Math.fround(( ~ Math.min(x, x))))), Math.fround(((42 >>> 0) % Math.fround(x))))))) | 0); }); testMathyFunction(mathy3, [0x07fffffff, -(2**53-2), 0x100000001, 1/0, 0x0ffffffff, -(2**53+2), Math.PI, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0x080000000, -Number.MIN_VALUE, -1/0, 42, 0x080000001, 1, 0.000000000000001, 2**53+2, 0, -0x100000001, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, -0x100000000, -0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1108; tryItOut("/*RXUB*/var r = 20; var s = \"\"; print(s.replace(r, function(y) { \"use strict\"; return true })); ");
/*fuzzSeed-248247344*/count=1109; tryItOut("mathy5 = (function(x, y) { return ((mathy0((Math.fround(x) | 0), (( + y) >>> 0)) | 0) ? ( ~ ( + (( + ( - -0)) ? Math.cbrt(( + x)) : -1/0))) : (Math.exp(Math.ceil(( + mathy1(x, ((Number.MIN_VALUE / (x - x)) | 0))))) | 0)); }); testMathyFunction(mathy5, [0.000000000000001, -0x080000001, -0x0ffffffff, 0/0, 0x100000000, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -0x07fffffff, -0x080000000, 0x0ffffffff, -(2**53-2), 0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, Number.MIN_VALUE, 0x100000001, -0x100000001, 0x080000000, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, 0, -1/0, -(2**53), 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=1110; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.asinh(Math.fround(( ~ (Math.ceil((y >>> 0)) | 0)))))); }); testMathyFunction(mathy3, [2**53+2, -0x07fffffff, -Number.MAX_VALUE, 1/0, 0, -(2**53+2), 0/0, -0x100000001, 0x080000000, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, -0, -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x080000001, 0.000000000000001, 2**53-2, Number.MAX_VALUE, -0x0ffffffff, -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, Math.PI, 42, -(2**53), 1]); ");
/*fuzzSeed-248247344*/count=1111; tryItOut("mathy4 = (function(x, y) { return ( + (Math.fround((Math.fround(Math.min((( ! (Math.atan2(x, ( + y)) >>> 0)) >>> 0), ( + mathy1(( + ( + Math.pow((y >>> 0), (1/0 | 0)))), ( + x))))) !== Math.fround(x))) >> ( + Math.fround(mathy1(( + (y + Math.round(x))), x))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 0x0ffffffff, -0x100000001, -0x100000000, 0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0, 1, -0x080000000, 0.000000000000001, -0x0ffffffff, 2**53+2, 0/0, 0x100000001, 42, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 1/0, Number.MAX_VALUE, -0x080000001, -(2**53-2), Math.PI, -Number.MIN_VALUE, 0, 1.7976931348623157e308, 2**53, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2]); ");
/*fuzzSeed-248247344*/count=1112; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s2, h2);");
/*fuzzSeed-248247344*/count=1113; tryItOut("g0.offThreadCompileScript(\"function f2(m1)  { yield (m1 == -15 = m1 = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: runOffThreadScript, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function(y) { \\\"use strict\\\"; yield y; b0.toString = (function() { for (var j=0;j<61;++j) { f0(j%5==0); } });; yield y; }, keys: function() { return []; }, }; })(undefined), (4277))) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 != 3), noScriptRval: false, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-248247344*/count=1114; tryItOut("/*oLoop*/for (vqplmb = 0; vqplmb < 0; ++vqplmb) { print(x); } ");
/*fuzzSeed-248247344*/count=1115; tryItOut("\"use strict\"; v1 = g0.runOffThreadScript();");
/*fuzzSeed-248247344*/count=1116; tryItOut("\"use strict\"; a0[0] = true;\n-9 = a1[5];\n");
/*fuzzSeed-248247344*/count=1117; tryItOut("\"use asm\"; /*ODP-3*/Object.defineProperty(g1.g1.m2, \"1\", { configurable: false, enumerable: [this], writable: (x % 4 != 0), value: f2 });");
/*fuzzSeed-248247344*/count=1118; tryItOut("/*infloop*/for(var e; (/*UUV2*/(\u3056.__lookupSetter__ = \u3056.entries).__defineSetter__(\"x\", 520930153)); (({/*toXFun*/toString: function(y) { yield y; v1 = false;; yield y; } }).valueOf(\"number\"))) print(x);");
/*fuzzSeed-248247344*/count=1119; tryItOut("\"use strict\"; t2 = new Float32Array(t1);");
/*fuzzSeed-248247344*/count=1120; tryItOut("t1[/*UUV1*/(b.toLocaleString = Uint32Array)] = v2;");
/*fuzzSeed-248247344*/count=1121; tryItOut("\"use strict\"; h2 + '';");
/*fuzzSeed-248247344*/count=1122; tryItOut("\"use strict\"; Array.prototype.push.apply(a2, [s0, x, let (d)  /x/ ]);");
/*fuzzSeed-248247344*/count=1123; tryItOut("let oygemi, x = x, \u3056, this.c = function ([y]) { } >=  /x/ ;for (var p in t2) { try { s2 = Array.prototype.join.apply(this.a2, [g1.s0, b1]); } catch(e0) { } try { print(x); } catch(e1) { } try { e1.has(e0); } catch(e2) { } t1[({valueOf: function() { return;return 12; }})] = NaN; }");
/*fuzzSeed-248247344*/count=1124; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.trunc(Math.fround(mathy0((Math.asin(( + (Math.fround(( + (y & ( + x)))) , Math.fround(x)))) ? ( ~ Math.fround(Math.max(Math.fround(( ~ x)), Math.fround(y)))) : Math.imul(( - y), (x * y))), ( ~ Math.fround((( - (2**53-2 ? x : ( + x))) <= x))))))); }); ");
/*fuzzSeed-248247344*/count=1125; tryItOut("\"use strict\"; {/* no regression tests found */Array.prototype.splice.apply(a0, [-4, 18]); }");
/*fuzzSeed-248247344*/count=1126; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround((((Math.atan2((Math.fround(Math.max(Math.acosh(x), x)) > y), (y >>> 0)) | 0) || (( - ( - x)) | 0)) | 0)) != Math.fround(((( ! Math.min(( + -(2**53-2)), ( + (Math.log2(1) >>> 0)))) >>> ( ! Math.atanh((x >>> x)))) >>> 0)))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -0x07fffffff, Math.PI, 42, Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, 1, 1.7976931348623157e308, -(2**53), Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, -1/0, -0x100000000, 2**53, -0, 0.000000000000001, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -0x100000001, -(2**53-2), 0x080000001, 0x100000001, Number.MAX_VALUE, 0x100000000, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1127; tryItOut("mathy4 = (function(x, y) { return Math.ceil((( + ( + ((mathy2(((x === Math.acosh(y)) | 0), (-0x07fffffff | 0)) | 0) << ((( ~ (y >>> 0)) >>> 0) >>> 0)))) >>> 0)); }); testMathyFunction(mathy4, [Math.PI, -0x080000001, 0x080000000, 0x07fffffff, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_VALUE, 0/0, -0x07fffffff, 0x0ffffffff, 2**53, 0, 0x100000001, 0.000000000000001, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), -1/0, 0x100000000, -0x080000000, Number.MAX_VALUE, 1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 1, 2**53-2, 2**53+2, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1128; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy2(((((( ! ( - x)) >>> 0) >>> 0) || Math.fround((( ! Math.acos((x / ((y || x) | 0)))) >>> 0))) | 0), (Math.acos((((( + x) | 0) & x) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=1129; tryItOut("this.f0(b0);");
/*fuzzSeed-248247344*/count=1130; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xfa7fbdfe);\n    {\n      i0 = (-0x8000000);\n    }\n    {\n      i0 = ((0x6128f710));\n    }\n    i0 = (0xffc09a2e);\n    return ((((((0xfcf833e1) < (0x40141416)) ? ((/*FFI*/ff()|0) ? ((-0x8000000) >= (0x7fffffff)) : (i0)) : ((((0xe0c8c9db))>>>((0x7503d01d))) != (((-0x8000000))>>>((0x5ff60367))))) ? (0x3f8c7e0e) : ((+(1.0/0.0))))))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[ \"use strict\" , 0x100000000, true, true,  /x/g ,  \"use strict\" , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  \"use strict\" ,  \"use strict\" , new Number(1), new Number(1), new Number(1),  /x/g ,  /x/g , 0x100000000, true, new Number(1),  /x/g , 0x100000000, new Number(1), new Number(1), new Number(1),  /x/g , true,  \"use strict\" , new Number(1), true, 0x100000000, new Number(1), true, new Number(1), true, true, true, new Number(1),  \"use strict\" , true, 0x100000000,  \"use strict\" ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  \"use strict\" , true, true,  /x/g ,  \"use strict\" , 0x100000000,  \"use strict\" , 0x100000000, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  /x/g ,  \"use strict\" ,  \"use strict\" , new Number(1), 0x100000000,  /x/g , new Number(1),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1), new Number(1), new Number(1), 0x100000000, new Number(1),  \"use strict\" ,  \"use strict\" , 0x100000000,  \"use strict\" , 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000,  /x/g , 0x100000000, true,  /x/g ,  \"use strict\" ,  \"use strict\" , true]); ");
/*fuzzSeed-248247344*/count=1131; tryItOut("/*bLoop*/for (fmcnkp = 0; fmcnkp < 77; ++fmcnkp) { if (fmcnkp % 115 == 50) { /*oLoop*/for (let oaaqyo = 0; oaaqyo < 32; ++oaaqyo) { g1.m1.has(g0); }  } else { m2 = new Map; }  } ");
/*fuzzSeed-248247344*/count=1132; tryItOut("with((4277))/*MARR*/[objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000001, 0x40000001, objectEmulatingUndefined(), 0x40000001, 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , 0x40000001,  /x/ , objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(), 0x40000001,  /x/ , 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), 0x40000001,  /x/ ,  /x/ , 0x40000001, 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000001, 0x40000001, objectEmulatingUndefined(), 0x40000001, 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), 0x40000001,  /x/ , 0x40000001, 0x40000001,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001,  /x/ , objectEmulatingUndefined(), 0x40000001, 0x40000001,  /x/ , 0x40000001, 0x40000001, 0x40000001, 0x40000001, objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000001, 0x40000001, 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , 0x40000001, 0x40000001, objectEmulatingUndefined(),  /x/ , 0x40000001, objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(), 0x40000001, objectEmulatingUndefined(),  /x/ , 0x40000001, 0x40000001, 0x40000001, objectEmulatingUndefined(), 0x40000001,  /x/ , 0x40000001,  /x/ ,  /x/ ,  /x/ , 0x40000001,  /x/ , 0x40000001,  /x/ , objectEmulatingUndefined(), 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, objectEmulatingUndefined(), 0x40000001, 0x40000001,  /x/ , 0x40000001, 0x40000001, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined()].map(function(y) { \"use strict\"; return -20 }, length);");
/*fuzzSeed-248247344*/count=1133; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( ! (Math.fround(((( ~ Math.cosh(x)) | 0) > (y - Math.fround(mathy0(Math.fround((0 * y)), y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0, (new Boolean(true)), ({toString:function(){return '0';}}), '0', NaN, null, undefined, (function(){return 0;}), objectEmulatingUndefined(), '', '\\0', (new Boolean(false)), /0/, [], ({valueOf:function(){return 0;}}), '/0/', 1, false, (new Number(0)), [0], (new Number(-0)), 0, ({valueOf:function(){return '0';}}), (new String('')), 0.1, true]); ");
/*fuzzSeed-248247344*/count=1134; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1135; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1136; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.pow(( ~ y), (( ! (Math.acos((Math.trunc(((( + (y >>> 0)) >>> 0) | 0)) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0x080000001, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, -0x07fffffff, 1, Math.PI, 0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), -0, 42, 2**53, 0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0.000000000000001, 0, -(2**53-2), -0x080000000, 1/0, 0/0, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1137; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var atan = stdlib.Math.atan;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        return ((((0xffffffff) ? (0xe7f911e) : ((~~(+pow((((void shapeOf(x)))), ((4097.0))))) == (((-0x8000000)-(i0)) | (((((0xd35fce9b)) & ((0xf41df73b))) <= (((0xff94a2a1)) >> ((0x36c2ab51))))))))))|0;\n      }\n    }\n    d1 = (17592186044417.0);\n    i0 = ((0xde958bca) < (0xaf0ca154));\n    (Float64ArrayView[(((0x1c5d8*((2251799813685247.0) != (4.835703278458517e+24))) >> (((0x9cf50e18) < (0x18b6dafe))-((0xf46ae7e8)))) % (~~(d1))) >> 3]) = ((d1));\n    (Float32ArrayView[((0xffffffff) % ((((0xc70df3c8) > (0x33848521))+((0x106a4d86) >= (0xf5eaf974)))>>>((0xa26103b0)))) >> 2]) = ((+(1.0/0.0)));\n    (Float32ArrayView[2]) = ((d1));\n    return (((0xffffffff)))|0;\n    {\n      {\n        d1 = (-4611686018427388000.0);\n      }\n    }\n    (Float64ArrayView[1]) = ((+atan(((524289.0)))));\n    return (((((((((d1) != (144115188075855870.0)))-((0xb451b61) <= (imul((i0), (/*FFI*/ff(((-4503599627370495.0)), ((1125899906842623.0)), ((-513.0)), ((64.0)))|0))|0))-(((0x48e2b*(0xe614e327)) | ((-0x2bdbc84) / (0x494c0298)))))|0)))*-0x6a6cd))|0;\n    return (((0x1fb6f20c) / ((0x9254e*(/*FFI*/ff(((+((+atan2(((+(0xffffffff))), ((d1))))))), (((((((0xf9178dc5))>>>((0xff607c24))))-(0x78d6b1f7))|0)), (((0x97a64af1) ? (9.44473296573929e+21) : (73786976294838210000.0))), ((-140737488355329.0)), ((d1)), ((-32769.0)), ((4095.0)), ((1.5474250491067253e+26)), ((3.0)), ((-524289.0)), ((144115188075855870.0)), ((1025.0)))|0))|0)))|0;\n    return (((0xe6578926)-(!(0xef6babd3))))|0;\n  }\n  return f; })(this, {ff: function(y) { M:with(yield Number.MAX_SAFE_INTEGER){s0 += 'x';(a);/*\n*/ } }}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_VALUE, 0, 42, 0.000000000000001, 2**53, -(2**53+2), -0, -0x080000000, 0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -(2**53), Number.MIN_VALUE, 0x0ffffffff, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0x100000001, -0x0ffffffff, -0x080000001, 1, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, -1/0, 0x07fffffff, -0x07fffffff, Math.PI, 0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=1138; tryItOut("mathy0 = (function(x, y) { return ( + ( + ( + Math.pow(Math.fround(Math.fround(Math.round(((( + y) % (y | 0)) >>> 0)))), Math.pow((((-Number.MAX_VALUE | 0) - (y - (( + (( + Math.log10(Math.fround(x))) | 0)) | 0))) | 0), x))))); }); ");
/*fuzzSeed-248247344*/count=1139; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - (( + ( - Math.fround(Math.acos((Math.sinh((-0x080000001 | 0)) | 0))))) >>> 0)); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -0x07fffffff, 0x080000000, 0/0, 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 2**53, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0, 42, -0x100000000, 1/0, Number.MIN_VALUE, -1/0, 0x100000001, 0x0ffffffff, -(2**53+2), -(2**53-2), 2**53-2, -0x080000000, -0x080000001, -0, 1, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x100000001]); ");
/*fuzzSeed-248247344*/count=1140; tryItOut("if(true) h0.getOwnPropertyDescriptor = f1; else  if (\u000c /x/ ) e2.has(t1); else print(x);");
/*fuzzSeed-248247344*/count=1141; tryItOut("mathy5 = (function(x, y) { return Math.log(( + ((( + Math.fround(Math.log1p(Math.fround(x)))) / ( + (Math.fround(Math.asin(Math.fround(-Number.MIN_VALUE))) / (x > x)))) == ( + ((( - Math.fround(y)) ? Math.fround(-Number.MIN_SAFE_INTEGER) : Math.fround((Math.fround(y) << y))) >= (Math.expm1(( + Math.imul(Math.PI, (-(2**53-2) | 0)))) < (y | 0))))))); }); ");
/*fuzzSeed-248247344*/count=1142; tryItOut("function shapeyConstructor(gmiirq){{ v1 = (s0 instanceof f0); } delete this[6];if (gmiirq) Object.defineProperty(this, \"1\", ({}));return this; }/*tLoopC*/for (let x of /*FARR*/[x, ,  \"\" , x]) { try{let vqvydq = shapeyConstructor(x); print('EETT'); o0 = o2.__proto__;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-248247344*/count=1143; tryItOut("\"use strict\"; v2 = t1.length;");
/*fuzzSeed-248247344*/count=1144; tryItOut("this.s1 += s1;");
/*fuzzSeed-248247344*/count=1145; tryItOut("\"use strict\"; /*RXUB*/var r = /[^]|\\3|(?!(?=$))|\\W+$(?!\\1{1}\\u0032{3,}|(?![^]\\b)?){3,5}/ym; var s = \"_\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-248247344*/count=1146; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + ( - ( + ( + (Math.atan(( ! mathy1(Math.log2(y), Math.log(x)))) >>> 0))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 1, -0x080000000, -0x0ffffffff, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 2**53-2, 0x080000000, -(2**53+2), 0x080000001, -0x07fffffff, -Number.MIN_VALUE, 0x100000000, 42, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, -0x080000001, 0x07fffffff, -(2**53), 2**53, 0x100000001, Math.PI, 0, Number.MAX_VALUE, -0, 2**53+2, 1.7976931348623157e308, -0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1147; tryItOut("/*vLoop*/for (lryhie = 0; lryhie < 28; ++lryhie) { e = lryhie; print(e); } ");
/*fuzzSeed-248247344*/count=1148; tryItOut("v0 = r2.toString;");
/*fuzzSeed-248247344*/count=1149; tryItOut("for (var v of e0) { try { v0 = 4.2; } catch(e0) { } try { a0 + ''; } catch(e1) { } v1 = (b2 instanceof p2); }");
/*fuzzSeed-248247344*/count=1150; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return (mathy2(Math.fround((Math.fround(Math.atanh((( ~ (x | 0)) | 0))) ? ( + ( - Math.acos(( ! (Math.hypot(y, (x | 0)) >>> 0))))) : Math.fround(( + ( - ( + ( + ( ! (Math.fround(Math.exp(Math.fround(x))) >>> 0))))))))), ((Math.sin(((Math.max(( ~ x), (Math.atan2(y, Math.fround((Math.hypot((x >>> 0), y) >>> 0))) | 0)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1151; tryItOut("mathy2 = (function(x, y) { return Math.tanh(( + ( + (Math.fround(Math.atan2(Math.fround(x), Math.fround(( ! Math.asin((Math.cos((0x100000000 >>> 0)) == Math.fround(-0x100000001))))))) ** ( + ( + Math.max((Math.fround(( + x)) >>> 0), (y >>> 0)))))))); }); testMathyFunction(mathy2, /*MARR*/[undefined, undefined, \"\\u1420\", \"\\u1420\", undefined,  \"use strict\" , \"\\u1420\", undefined, undefined, \"\\u1420\",  \"use strict\" , \"\\u1420\", undefined, \"\\u1420\", undefined, \"\\u1420\", \"\\u1420\",  \"use strict\" , \"\\u1420\",  \"use strict\" ,  \"use strict\" ,  \"use strict\" , \"\\u1420\", \"\\u1420\",  \"use strict\" , \"\\u1420\", undefined, undefined, undefined,  \"use strict\" , \"\\u1420\", \"\\u1420\", undefined, \"\\u1420\", \"\\u1420\", \"\\u1420\", undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, \"\\u1420\", undefined, \"\\u1420\", undefined, \"\\u1420\",  \"use strict\" , undefined, undefined, undefined, undefined,  \"use strict\" ,  \"use strict\" , undefined, \"\\u1420\", \"\\u1420\", undefined, \"\\u1420\", \"\\u1420\"]); ");
/*fuzzSeed-248247344*/count=1152; tryItOut("testMathyFunction(mathy5, /*MARR*/[new Number(1.5), true, new Number(1.5), new Number(1.5), this, new Number(1.5), new Number(1.5), new Number(1.5), this, true, this, true, new Number(1.5), true, new Number(1.5), this, this, true, this, new Number(1.5), this, new Number(1.5), new Number(1.5), true, new Number(1.5), true, this, this, new Number(1.5), true, new Number(1.5), this, true, this, true, this, true, true, true, true, true, true, new Number(1.5), new Number(1.5), true, true, true, this, new Number(1.5), true, new Number(1.5), new Number(1.5), true, this, new Number(1.5), new Number(1.5), this, true, new Number(1.5), new Number(1.5), new Number(1.5), this, new Number(1.5), true, true, this, new Number(1.5), new Number(1.5), this, this, true, this, this, true, this, this, this, true, new Number(1.5), this, true, true, this, true, true, true, true, this, new Number(1.5), new Number(1.5), true, true, true, this, true, this, true, new Number(1.5)]); ");
/*fuzzSeed-248247344*/count=1153; tryItOut("\"use strict\"; /*infloop*/M:for(let [arguments, {}] = null;  '' ; Object.defineProperty(y, \"asin\", ({}))) {i0.next();m1 = new Map; }");
/*fuzzSeed-248247344*/count=1154; tryItOut("const v1 = r2.sticky;");
/*fuzzSeed-248247344*/count=1155; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (!(i0));\n    {\n      i1 = (i1);\n    }\n    i1 = (/*FFI*/ff(((((0xa93e0f61)) >> ((i1)*0xfffff))))|0);\n    {\n      (Uint8ArrayView[(0x51974*((-536870913.0) <= (Infinity))) >> 0]) = ((0x6adcc26d)+((0xbc51b8d) <= (((i0)) & ((i0)+(0xdc6008c2))))+(i1));\n    }\n    i0 = ((9.671406556917033e+24) != (Infinity));\n    return +((1073741825.0));\n    {\n      i0 = (((((((i1)) << (((0x34d741e4) < (0x1f61062)))))+(i1))>>>(((i0) ? (i1) : (i1)))));\n    }\n    i1 = (i0);\n    i1 = (/*FFI*/ff()|0);\nprint(x);    (Uint8ArrayView[((i1)-(i0)) >> 0]) = ((i0)-((((-((((-2049.0)) - ((-576460752303423500.0)))))) - ((-36893488147419103000.0))) == (NaN)));\n    i0 = ((~~(-((+(1.0/0.0))))) != ((-0xdb708*(/*FFI*/ff(((+/*FFI*/ff())))|0))|0));\n    {\n      i0 = (((i0)) > (-65.0));\n    }\n    (Float32ArrayView[(((((i1)) << ((i1))))) >> 2]) = ((257.0));\n    i0 = ((((eval(\"/* no regression tests found */\"))+((4277)))|0) > ((((2147483649.0) != (+floor(((-1.888946593147858e+22)))))+(i1)) >> ((/*FFI*/ff((((((-18014398509481984.0) >= (-72057594037927940.0))+(i1)) >> ((0xffffffff) / (0xc5ef017)))))|0)+(i0))));\n    i1 = (!(/*FFI*/ff()|0));\n    i0 = (i0);\n    ((4277)) = ((-16385.0));\n    i1 = ((((i0))>>>((i0))) >= (((0xfdf912c3)+(i1))>>>((i1))));\n    return +((9.671406556917033e+24));\n  }\n  return f; })(this, {ff: String.prototype.anchor}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_VALUE, 42, -0x080000000, -(2**53+2), -0x0ffffffff, -0x100000001, 0x080000001, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, 1, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, -(2**53), -0x080000001, -0x07fffffff, -0, 0x100000001, 0x080000000, 0/0, Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, 2**53+2, 1/0, Math.PI, 0x100000000, 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1156; tryItOut("\"use strict\"; h2.getPropertyDescriptor = f2;");
/*fuzzSeed-248247344*/count=1157; tryItOut("mathy2 = (function(x, y) { return mathy1(((Math.fround(( + (Math.atan2((mathy1(y, ( - y)) >>> 0), (y >>> 0)) >>> 0))) | 0) <= Math.fround(Math.pow(Math.fround(( - (Math.round((Math.sinh((y | 0)) | 0)) | 0))), Math.sign(Math.fround(( - x)))))), mathy1((Math.hypot(-0x07fffffff, y) != x), (y ^ ( + 1.7976931348623157e308)))); }); testMathyFunction(mathy2, [-(2**53), -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 2**53-2, -0x080000001, 0.000000000000001, 0x080000001, -(2**53-2), 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, 0x07fffffff, 1, -0x100000001, Number.MAX_VALUE, -0x080000000, 0, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, 42, -0, 0/0, 0x100000000, 2**53, 0x0ffffffff, -Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-248247344*/count=1158; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.clz32((Math.fround(Math.log2((Math.acosh(((0x100000000 ** ( ! (x >>> 0))) == -0x080000001)) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-248247344*/count=1159; tryItOut("testMathyFunction(mathy5, /*MARR*/[true, [], [], true, true, [], [], true, true, [], true, [], [], true, true, [], [], [], [], true, [], [], true, true, true, [], [], [], true, true, true, true, [], [], [], true, [], true, true, true, [], true, true, true, [], true, [], true, [], true, true, true, true]); ");
/*fuzzSeed-248247344*/count=1160; tryItOut("a2 = new Array(0);");
/*fuzzSeed-248247344*/count=1161; tryItOut("/*MXX3*/g1.Math.pow = g1.Math.pow;");
/*fuzzSeed-248247344*/count=1162; tryItOut("\"use strict\"; /*RXUB*/var r = /.|${3,}{16777216,16777216}/im; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-248247344*/count=1163; tryItOut("mathy4 = (function(x, y) { return mathy0(Math.min(( + ( ~ (mathy0(((-0x0ffffffff ? ( + x) : ( + x)) >>> 0), Number.MAX_VALUE) >>> 0))), ( ~ Math.ceil((Math.fround(x) >>> 0)))), (((( - Math.min(((( + x) | 0) ? y : ((Math.fround(( - (y >>> 0))) / (Math.acos((x >>> 0)) >>> 0)) >>> 0)), Math.fround(mathy3(Math.fround(Math.asinh(x)), Math.fround(x))))) | 0) == (( - Math.fround(y)) | 0)) | 0)); }); testMathyFunction(mathy4, ['0', '/0/', true, false, (new Boolean(false)), /0/, (new Number(0)), [], (new String('')), (new Boolean(true)), (function(){return 0;}), 0, [0], undefined, ({valueOf:function(){return '0';}}), '\\0', '', ({toString:function(){return '0';}}), 0.1, objectEmulatingUndefined(), -0, NaN, ({valueOf:function(){return 0;}}), null, 1, (new Number(-0))]); ");
/*fuzzSeed-248247344*/count=1164; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.asin(( ~ ( + Math.cos(Math.sinh(Math.fround((Math.fround(x) ^ Math.fround(Math.fround(Math.max(x, y)))))))))); }); testMathyFunction(mathy3, [0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, 1/0, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 42, -(2**53), Math.PI, 0x080000000, 0, -0x080000000, -0x080000001, -(2**53-2), -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, -0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, -(2**53+2), 0x100000000, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 1, -1/0, 2**53+2, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1165; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ! ( + Math.min((y ? Number.MAX_SAFE_INTEGER : (( + (x | 0)) | 0)), (x , x))))); }); testMathyFunction(mathy3, [-(2**53-2), 0x080000001, -0x100000001, 0x100000000, 0.000000000000001, 1, -0x07fffffff, -0x0ffffffff, 2**53+2, 2**53-2, 42, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, -1/0, -(2**53+2), 1/0, 0x100000001, 1.7976931348623157e308, -0x080000001, -Number.MAX_VALUE, 0/0, 0x080000000, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, 0, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, 0x07fffffff, -Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1166; tryItOut("\"use strict\"; i2 + '';");
/*fuzzSeed-248247344*/count=1167; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1168; tryItOut("v0 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-248247344*/count=1169; tryItOut("\"use strict\"; h0.toString = (function() { try { v1 = evaluate(\"/*infloop*/for(w; z; /(?:(?!\\\\2*?)*|\\\\D([\\\\u0019n-\\\\udc20\\\\n-\\\\cC]?.|([\\\\cI-\\u7a40\\\\u002b-\\u00c7\\\\d]\\\\w)|[^]^*?))/yim) (-27);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: x, catchTermination: (void options('strict_mode')), element: o2 })); } catch(e0) { } this.m2.get(v1); return this.f2; });");
/*fuzzSeed-248247344*/count=1170; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.min(( + (x !== x)), Math.imul(Math.log1p((Math.tanh(Math.fround((mathy0(Math.fround(x), Math.fround(x)) | 0))) | 0)), x)) ? mathy2(( ~ (mathy0((y >= Math.fround(x)), Math.fround(y)) | 0)), Math.fround(Math.pow(( + (y === (Math.fround(( ! Math.fround(-0x07fffffff))) | 0))), mathy1((x ? y : 0x080000000), ( + y))))) : Math.pow(((Math.log((Math.min(x, x) >>> 0)) | 0) < (mathy0(( + x), y) | 0)), Math.hypot(mathy0((-0 <= y), (mathy1(x, ( + x)) >>> 0)), ( + ((((Math.abs(x) >>> 0) < ( + x)) >>> 0) && x))))) ? mathy2(Math.fround(Math.exp(0x0ffffffff)), Math.fround(Math.expm1(Math.fround((x >= Math.fround((Math.imul(x, (y - x)) <= Math.exp(x)))))))) : Math.fround(Math.atan2(Math.fround((Math.max(((x >>> 0) , (x >>> 0)), ( + x)) & Math.fround((x != Math.fround(Math.ceil(Math.fround(Math.fround((( + x) ^ ((x > x) | 0)))))))))), (Math.imul(( - x), ( + Math.atanh(2**53+2))) | 0)))); }); testMathyFunction(mathy3, [0, ({valueOf:function(){return 0;}}), (new Number(0)), -0, (new String('')), undefined, 1, ({toString:function(){return '0';}}), false, (new Boolean(true)), NaN, (function(){return 0;}), null, true, '\\0', '/0/', '0', /0/, objectEmulatingUndefined(), [0], ({valueOf:function(){return '0';}}), '', [], 0.1, (new Number(-0)), (new Boolean(false))]); ");
/*fuzzSeed-248247344*/count=1171; tryItOut("testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 1/0, -0x080000000, 0x07fffffff, 0x080000001, 2**53, -0x100000000, 0, 0/0, -0x100000001, -0x0ffffffff, -0, Number.MIN_VALUE, 0x100000001, 0x0ffffffff, -0x080000001, -(2**53+2), 2**53-2, 0x100000000, 1, 0x080000000, -(2**53), Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42]); ");
/*fuzzSeed-248247344*/count=1172; tryItOut("\"use strict\"; /*infloop*/ for  each(var NaN in \u000c(void options('strict'))) print(i1);");
/*fuzzSeed-248247344*/count=1173; tryItOut("t0 = new Uint8Array(a2);");
/*fuzzSeed-248247344*/count=1174; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.hypot(( + ( + ( ~ ( + ( ~ ( ! ( + Math.fround(Math.log10(Math.fround(x)))))))))), (Math.hypot(Math.fround(Math.log(Math.fround(0x0ffffffff))), Math.atan2((Math.fround(x) >= Math.fround(((y != (Math.sinh(Number.MIN_VALUE) >>> 0)) <= y))), (Math.pow((y !== -Number.MAX_SAFE_INTEGER), ( + ( + ((( ~ ( + x)) >>> 0) ? -Number.MAX_VALUE : x)))) >>> 0))) | 0))); }); testMathyFunction(mathy1, [-0x080000001, Number.MIN_VALUE, 2**53, 0, 2**53+2, 1, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 42, 2**53-2, -Number.MAX_VALUE, -(2**53+2), -0x100000000, 0x100000000, 1.7976931348623157e308, 0x07fffffff, -1/0, -0x07fffffff, Number.MAX_VALUE, Math.PI, -0, 1/0, -0x0ffffffff, 0x080000001, -0x080000000, 0/0, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=1175; tryItOut("mathy5 = (function(x, y) { return (((( + mathy1(( + ((((Math.imul(((( - ( + y)) >>> 0) >>> 0), ((( ! (Math.fround(Math.hypot((-0x0ffffffff >>> 0), Math.fround(0x07fffffff))) | 0)) | 0) >>> 0)) >>> 0) >>> 0) > (Math.atan2(Math.fround((Number.MIN_SAFE_INTEGER ^ x)), (Math.log2(x) >>> 0)) >>> 0)) >>> 0)), ( + Math.fround(mathy2(( + Math.sign(( + ( - Math.fround(x))))), (mathy0(y, (Math.max((( + Math.hypot(( + x), ( + x))) >>> 0), -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)))))) | 0) !== (Math.hypot(( + Math.atan2(( + ((mathy3((Math.PI >>> 0), (y | 0)) | 0) >>> ( + (((x >>> 0) <= y) >>> 0)))), ( + Math.fround(( - Math.fround((mathy2((y | 0), (y | 0)) | 0))))))), ( ~ ( ! y))) | 0)) | 0); }); testMathyFunction(mathy5, [0, 1, -(2**53-2), 2**53+2, 2**53, -(2**53), -0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, Math.PI, -1/0, 0/0, 1.7976931348623157e308, 0x080000001, -0x07fffffff, 42, 0x100000000, 1/0, 0x0ffffffff, 2**53-2, -0x080000001, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -0x100000000, -Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-248247344*/count=1176; tryItOut("\"use strict\"; /*vLoop*/for (var uzlgvy = 0; uzlgvy < 42; ++uzlgvy) { let w = uzlgvy; (7); } ");
/*fuzzSeed-248247344*/count=1177; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( ! (Math.fround((Math.fround(Math.fround(Math.imul(Math.fround((Math.tan(Math.fround(y)) + x)), Math.fround(y)))) & Math.fround(y))) >>> 0))); }); testMathyFunction(mathy0, [0/0, -0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -0, -Number.MAX_SAFE_INTEGER, Math.PI, 1, 0x07fffffff, 1/0, 0.000000000000001, 0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, -(2**53-2), -0x0ffffffff, 2**53-2, -Number.MIN_VALUE, 0x100000000, -0x100000001, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -(2**53), 42, 0, 0x100000001, -0x080000001, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1178; tryItOut("let (knmnoe, ehxter) { return \"\\u6454\"; }");
/*fuzzSeed-248247344*/count=1179; tryItOut("/*RXUB*/var r = /(?:(?=[^\\S\\u0085]|\\1)|[\\SH-\\x48\\u0000]|..*|(?=[^=-\u00b1]).{3,5}|(?:[^\\d\\ub1Ea\\d\\f-\u0d93]|\\3)*|\\b{3,8589934596})/yim; var s = \"a\"; print(r.exec(s)); ");
/*fuzzSeed-248247344*/count=1180; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a2, [(4277).__defineSetter__(\"x\", Promise.prototype.catch)]);");
/*fuzzSeed-248247344*/count=1181; tryItOut("/*RXUB*/var r = r2; var s = s1; print(s.split(r)); ");
/*fuzzSeed-248247344*/count=1182; tryItOut("delete g0.g0.h2.get;");
/*fuzzSeed-248247344*/count=1183; tryItOut("this.m0 = a2[13];");
/*fuzzSeed-248247344*/count=1184; tryItOut("\"use strict\"; m1.toSource = (function mcc_() { var jmfloj = 0; return function() { ++jmfloj; if (/*ICCD*/jmfloj % 7 == 2) { dumpln('hit!'); try { v2 = Object.prototype.isPrototypeOf.call(g1.p1, b0); } catch(e0) { } v2 = evalcx(\"v2 = this.g0.runOffThreadScript();\", g1); } else { dumpln('miss!'); e1.delete(h0); } };})();");
/*fuzzSeed-248247344*/count=1185; tryItOut("\"use strict\"; \"use asm\"; Object.seal(g2)");
/*fuzzSeed-248247344*/count=1186; tryItOut("\"use strict\"; /*infloop*/for(var (4277)[\"w\"] in w) {/*MXX1*/o1 = g1.Array.prototype.shift;delete g2.m0[\"revocable\"]; }");
/*fuzzSeed-248247344*/count=1187; tryItOut("f1(e1);");
/*fuzzSeed-248247344*/count=1188; tryItOut("b2 + g2;");
/*fuzzSeed-248247344*/count=1189; tryItOut("mathy1 = (function(x, y) { return (mathy0((( ! Math.fround(( + ( ~ y)))) | 0), (( + (Math.imul((x | 0), (y | 0)) | 0)) ^ ( + (( + y) / ( + mathy0((y >>> 0), (mathy0(x, (Math.hypot((y >>> 0), x) >>> 0)) >= Math.fround(y)))))))) | 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, 0x080000000, -0x080000001, -0x080000000, 42, -Number.MIN_VALUE, Math.PI, -0, -(2**53-2), 0, -0x100000000, -(2**53), 1, 0/0, 0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 2**53+2, Number.MIN_VALUE, 1/0, 1.7976931348623157e308, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), 2**53]); ");
/*fuzzSeed-248247344*/count=1190; tryItOut("mathy4 = (function(x, y) { return (mathy0((( - Math.min(Math.min((Math.imul((( + x) >>> 0), -0x100000001) >>> 0), (0x080000001 >>> 0)), Math.fround(( ~ ( + ( ! 2**53-2)))))) | 0), ((( ~ ((( - Math.fround((Math.fround(0x080000000) * Math.fround(Math.abs((Math.min(x, x) | 0)))))) | 0) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [objectEmulatingUndefined(), null, (new Boolean(true)), '\\0', '', false, (new Number(-0)), [0], -0, (new Boolean(false)), (new Number(0)), 0.1, '/0/', ({valueOf:function(){return '0';}}), '0', ({valueOf:function(){return 0;}}), NaN, undefined, /0/, (function(){return 0;}), (new String('')), ({toString:function(){return '0';}}), [], 1, 0, true]); ");
/*fuzzSeed-248247344*/count=1191; tryItOut("mathy1 = (function(x, y) { return ( ! Math.sqrt(Math.sin(( + mathy0(( + y), ( + (Math.cbrt(x) >>> 0))))))); }); testMathyFunction(mathy1, [1/0, 2**53+2, -(2**53+2), Math.PI, -0x100000001, -0, -0x0ffffffff, 0.000000000000001, -1/0, -Number.MAX_VALUE, 42, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, 0/0, -0x100000000, 0x080000001, -0x07fffffff, -0x080000000, 0, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53), Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-248247344*/count=1192; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[new String('q'), null, null, true, true, new String('q'), null, new String('q'), new String('q'), true, new String('q'), true, new String('q'), true, null, true, null, null, null, true, new String('q'), true, null, new String('q'), true, new String('q'), new String('q'), null]) { print(x); }function NaN([{x: [, w, [x, {x, x, x: {z: [, []]}, x: {\u3056: x}}], , ], \u3056, w: {e, x: [, x], e: {}}, x: c}, {}, , {d: z, x}, {e: [], b: {b: {NaN: {y: {window: [], e: {y: [], d}, eval: {z, b}}, \u3056: z, e: {}}, eval: {NaN, x}}}, b, \u3056: [, , {c: {b: [a, x, ], x: [{e}, ], x: []}\u000d, b, b, x, eval}], e, y}], x) { yield (4277) } a0.unshift();");
/*fuzzSeed-248247344*/count=1193; tryItOut("\"use strict\"; a2.shift(new Array((b !== new ((4277))((void options('strict')))), new ((this.__defineGetter__(\"valueOf\", String.prototype.charAt)))()), g1.h2, x++((EvalError).call( /x/ , 2, \"\\u2774\")) instanceof ((4277) >>> (({}).watch(\"-18\", Map))));");
/*fuzzSeed-248247344*/count=1194; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1195; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.asin(((( + (Math.fround(Math.clz32(Math.fround(Math.pow(Math.fround(Math.fround(Math.hypot(( + mathy0(0x080000000, Math.fround(x))), (x >>> 0)))), Math.fround(( + (( + x) ** ( + y)))))))) ^ ( + ( + (( + Math.hypot((x | 0), y)) ** Math.fround(x)))))) , ((((y | 0) / Math.log(Math.fround(y))) | 0) ? Math.fround(mathy0(x, mathy0((x >>> 0), (Math.fround(( + (y | 0))) >>> 0)))) : (( ~ (Math.pow(-Number.MAX_SAFE_INTEGER, Math.trunc(y)) >>> 0)) >>> 0))) | 0))); }); testMathyFunction(mathy1, [-0x0ffffffff, Number.MIN_VALUE, 0x0ffffffff, -0, 0x100000001, 2**53+2, -0x080000000, 2**53, 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 42, 0, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x100000001, 1, -(2**53-2), -1/0, -0x080000001, -Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000001, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), 0/0, 0x080000000]); ");
/*fuzzSeed-248247344*/count=1196; tryItOut("yield window;s1 = new String(p0);");
/*fuzzSeed-248247344*/count=1197; tryItOut("\"use asm\"; a2 = Array.prototype.concat.call(a1);");
/*fuzzSeed-248247344*/count=1198; tryItOut("mathy3 = (function(x, y) { return (( ! ((Math.imul(Math.fround((Math.fround(y) >> -(2**53+2))), (Math.fround(-Number.MAX_VALUE) === ( + (x ** ( + x))))) === Math.max((Math.trunc(( + x)) >>> 0), (y >>> 0))) | 0)) != Math.atan2(Math.fround(((( - Math.fround(mathy0(Math.fround(( ~ Math.atanh(y))), Math.fround(x)))) > (Math.fround((Math.fround(( + Math.max(( + -Number.MIN_SAFE_INTEGER), ( + x)))) & (Math.fround((Math.fround(Math.fround(( ! Math.fround(Math.log1p((y >>> 0)))))) < Math.fround((y << Math.fround(( + Math.fround(y))))))) | 0))) | 0)) | 0)), Math.fround(Math.round(Math.ceil(-Number.MAX_SAFE_INTEGER))))); }); testMathyFunction(mathy3, [Math.PI, 0x100000001, -Number.MIN_VALUE, -(2**53-2), 42, 1, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -0x080000001, 0x100000000, -0x100000001, -(2**53+2), 1/0, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 2**53+2, 0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 0, -(2**53), -1/0, -0, 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1199; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( - ( + (( - (((Math.fround((x ** ( + Math.hypot(Math.fround(( + ( + y))), y)))) != Math.fround(Math.max(y, (Math.asinh((( ~ ( + y)) >>> 0)) >>> 0)))) >>> 0) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-248247344*/count=1200; tryItOut("\"use strict\"; do print((4277)); while((x !== false.delete(b)) && 0);function z(NaN = (void options('strict')), {x: {NaN, x, x: {}}}) { \"use asm\"; Array.prototype.push.apply(this.a1, [intern( \"\" ), f0]); } /*ODP-1*/Object.defineProperty(m2, \"11\", ({set: String.prototype.startsWith, enumerable: true}));");
/*fuzzSeed-248247344*/count=1201; tryItOut("Array.prototype.forEach.call(a2);");
/*fuzzSeed-248247344*/count=1202; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1203; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1204; tryItOut("\"use strict\"; \"use asm\"; var lbhtth = new ArrayBuffer(8); var lbhtth_0 = new Uint32Array(lbhtth); Object.defineProperty(this, \"g0\", { configurable: \"\\uC001\", enumerable: true,  get: function() {  return this; } });");
/*fuzzSeed-248247344*/count=1205; tryItOut("h1 = ({getOwnPropertyDescriptor: function(name) { t0 = new Float64Array(a0);; var desc = Object.getOwnPropertyDescriptor(e2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { r0 = /[^][^\\D]/im;; var desc = Object.getPropertyDescriptor(e2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { g2.v2 = a1.every((function() { try { a2.push(window); } catch(e0) { } for (var v of b0) { try { v2 = g2.eval(\"/* no regression tests found */\"); } catch(e0) { } g0.s1 = new String; } return h2; }));; Object.defineProperty(e2, name, desc); }, getOwnPropertyNames: function() { Array.prototype.push.apply(a0, [p1, this.p1, o1]);; return Object.getOwnPropertyNames(e2); }, delete: function(name) { s2 = new String(p2);; return delete e2[name]; }, fix: function() { m1.has(b0);; if (Object.isFrozen(e2)) { return Object.getOwnProperties(e2); } }, has: function(name) { Array.prototype.reverse.call(a1);; return name in e2; }, hasOwn: function(name) { for (var v of h1) { try { e2 + ''; } catch(e0) { } try { h2.getOwnPropertyNames = g0.f2; } catch(e1) { } try { this.v2 = new Number(i0); } catch(e2) { } b0 + ''; }; return Object.prototype.hasOwnProperty.call(e2, name); }, get: function(receiver, name) { p1.toString = (function() { try { h0 = {}; } catch(e0) { } try { (void schedulegc(g1)); } catch(e1) { } try { g0.p2 + ''; } catch(e2) { } s0 = ''; return o0; });; return e2[name]; }, set: function(receiver, name, val) { return m2; e2[name] = val; return true; }, iterate: function() { v2 = Object.prototype.isPrototypeOf.call(s1, v0);; return (function() { for (var name in e2) { yield name; } })(); }, enumerate: function() { v0 = (this.a2 instanceof v2);; var result = []; for (var name in e2) { result.push(name); }; return result; }, keys: function() { i2.next();; return Object.keys(e2); } });\nprint(x);\n");
/*fuzzSeed-248247344*/count=1206; tryItOut("h0.valueOf = (function() { for (var j=0;j<0;++j) { f1(j%5==0); } });");
/*fuzzSeed-248247344*/count=1207; tryItOut("\"use strict\"; while((allocationMarker()) && 0){v0 = a1.length;/*RXUB*/var r = new RegExp(\"\\\\3{0,2}\", \"gm\"); var s = \"\\n\\u6319a\"; print(uneval(r.exec(s)));  }");
/*fuzzSeed-248247344*/count=1208; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( - Math.hypot((Math.fround(Math.pow((Math.hypot(Math.min(y, Number.MAX_SAFE_INTEGER), (( + Math.acos((1.7976931348623157e308 >>> 0))) >>> 0)) >>> 0), Math.fround(x))) | 0), Math.acos((Math.tan(Math.fround((( ! (x | 0)) | 0))) | 0)))) | 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -(2**53), 0/0, 1/0, -1/0, -0x080000001, 0x080000001, 2**53-2, -Number.MAX_VALUE, -(2**53+2), -0x080000000, 0, 0.000000000000001, -(2**53-2), 0x100000001, -0x100000001, -0, 0x0ffffffff, 0x080000000, -0x100000000, 2**53+2, 0x07fffffff, 1, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, Math.PI, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=1209; tryItOut("\"use strict\"; /*oLoop*/for (var cbezpo = 0, new Int16Array(); cbezpo < 112; ++cbezpo) { let (y) { v0 = g0.eval(\"((Object.entries)(new (undefined)(new RegExp(\\\"(?:[^]+?)\\\", \\\"gyim\\\")), (this.watch(\\\"constructor\\\", undefined))))\"); } } ");
/*fuzzSeed-248247344*/count=1210; tryItOut("/*ADP-2*/Object.defineProperty(a1, v0, { configurable: false, enumerable: (x % 65 != 22), get: (function(j) { if (j) { try { a1.forEach(h2); } catch(e0) { } try { g0 + h2; } catch(e1) { } try { v2 = g1.runOffThreadScript(); } catch(e2) { } print(a2); } else { try { return;with({}) { for(let z of /*MARR*/[-(2**53-2), (1/0), -(2**53-2), (1/0), -(2**53-2), -(2**53-2)]) return; }  } catch(e0) { } try { s2 += 'x'; } catch(e1) { } this.o0.g1.m1.delete((4277)); } }), set: (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      (Float32ArrayView[(((0x1f70bf2c) >= (((0x5531bf02) % (0x6ae93826))>>>((0xf7206a55) / (0x536009a0))))+(!((((-0x8000000)) | ((0x4defb026))) < (imul((0xe064010e), (0x3016987a))|0)))) >> 2]) = ((16384.0));\n    }\n    d0 = (((d0) + (9223372036854776000.0)) + (NaN));\n    /*FFI*/ff(((((-3.777893186295716e+22)) / ((d1)))), ((abs((((((0xffffffff))>>>((0x4354f9d6))) / (0xd0d8ca7f)) << (((9223372036854776000.0) >= (524289.0))*0x4a983)))|0)), ((imul((0x60a3ffd9), ((0x49a2b8e6) ? (0x742db858) : (0x617503af)))|0)));\n    (Float64ArrayView[2]) = ((d0));\n    i2 = (/*FFI*/ff(((-17592186044417.0)), (((0xd411b13a) ? (9.44473296573929e+21) : (d0))))|0);\n    i2 = (-0x8000000);\n    {\n      i2 = ((((0xffffffff)+(-0x8000000)-(i2))>>>((-0x8000000))));\n    }\n    d0 = (70368744177664.0);\n    d1 = (67108865.0);\n    {\n      d0 = (d1);\n    }\n    return +((Float64ArrayView[0]));\n  }\n  return f; })(this, {ff: Math.hypot(5, c = /((?:(?:\u009d*){2,}))/y)}, new SharedArrayBuffer(4096)) });");
/*fuzzSeed-248247344*/count=1211; tryItOut("\"use strict\"; print([] = this.zzz.zzz.unwatch(\"wrappedJSObject\"));");
/*fuzzSeed-248247344*/count=1212; tryItOut("\"use strict\"; var rftbwe = new ArrayBuffer(0); var rftbwe_0 = new Uint8Array(rftbwe); print(rftbwe_0[0]); var rftbwe_1 = new Float32Array(rftbwe); print(rftbwe_1[0]); rftbwe_1[0] = -28; var rftbwe_2 = new Uint8ClampedArray(rftbwe); rftbwe_2[0] = -2; var rftbwe_3 = new Float64Array(rftbwe); var rftbwe_4 = new Uint32Array(rftbwe); var rftbwe_5 = new Uint8Array(rftbwe); rftbwe_5[0] = 27; var rftbwe_6 = new Float64Array(rftbwe); print(rftbwe_6[0]); v1 = a0.some((function() { try { t0 = new Uint16Array(b1, 64, 7); } catch(e0) { } a1 = Array.prototype.filter.apply(a1, [(function mcc_() { var fqwrcq = 0; return function() { ++fqwrcq; this.f2(/*ICCD*/fqwrcq % 7 == 3);};})()]); return g2; }), \"\\u168C\");undefined;/*ODP-2*/Object.defineProperty(this.b0, \"1\", { configurable: /\\3$|(?=\ua5b0)\u1f67?+\\2{1,}/y, enumerable: (rftbwe_5[0] % 6 != 2), get: (function() { try { t2 = t2.subarray(({valueOf: function() { for (var v of g0.e1) { try { s0 += s1; } catch(e0) { } try { Array.prototype.shift.apply(a1, [g2.b0, h2, i0, o1.p0, i0]); } catch(e1) { } a0[2] = g0.b1; }return 6; }})); } catch(e0) { } v1 = evaluate(\"f0.toString = (function() { try { print(g0.i2); } catch(e0) { } try { v0 = (o0 instanceof o2.g1); } catch(e1) { } try { m0 + ''; } catch(e2) { } this.t1 = new Int32Array(b2); return o1.e2; });\", ({ global: this.o0.g0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: /[^]|[^][^]/gyi, sourceIsLazy: \"\u03a0\", catchTermination: false })); return g1; }), set: (function() { for (var j=0;j<36;++j) { this.f1(j%2==1); } }) });( /x/g );print(rftbwe_2);this.g2.a2.unshift(v0, p0);");
/*fuzzSeed-248247344*/count=1213; tryItOut("mathy3 = (function(x, y) { return Math.max(( + (( + Math.max(x, Math.fround(Math.ceil(Math.fround(-Number.MIN_VALUE))))) <= ( + Math.fround(Math.atan2(Math.fround(Math.asin((x >>> 0))), Math.fround((Math.fround(Math.log2((( + (( + x) ? ( + y) : x)) >>> 0))) ? y : (y | 0)))))))), Math.hypot(( - Math.cbrt(mathy1(( + Math.round(Math.fround(( ~ 0x080000001)))), x))), Math.fround(Math.acosh(Math.atan2(( + 0/0), x))))); }); testMathyFunction(mathy3, [2**53, -(2**53-2), 0x0ffffffff, 0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0, -(2**53), 0x100000001, 1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000001, 1, -Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 2**53-2, -Number.MIN_VALUE, -0x07fffffff, 0/0, -0x0ffffffff, Math.PI, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, -1/0, -0x080000000, -0, 42]); ");
/*fuzzSeed-248247344*/count=1214; tryItOut("print(x);");
/*fuzzSeed-248247344*/count=1215; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1216; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atanh((Math.fround(Math.min(Math.fround(Math.log10(y)), Math.fround(( ! x)))) | ( ! mathy0(( + ( ~ ( + 0/0))), ( + (x ? -(2**53) : Math.sign(( + y))))))))); }); testMathyFunction(mathy5, [2**53-2, -0x080000001, 0x0ffffffff, 0.000000000000001, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, -1/0, -Number.MIN_VALUE, 0/0, 2**53+2, -(2**53), 0x080000000, -0x080000000, -0x100000001, -0x100000000, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), -0x07fffffff, -(2**53+2), 1/0, Number.MIN_VALUE, -0, -Number.MAX_VALUE, Math.PI, 42]); ");
/*fuzzSeed-248247344*/count=1217; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( - Math.fround(( ! Math.fround(( ~ Math.fround(Math.fround((Math.fround(x) || Math.fround(( + x)))))))))); }); testMathyFunction(mathy0, [(new String('')), '/0/', [0], ({valueOf:function(){return 0;}}), 0, 0.1, ({valueOf:function(){return '0';}}), (new Boolean(true)), (new Boolean(false)), '\\0', /0/, (new Number(-0)), NaN, [], -0, '', null, objectEmulatingUndefined(), undefined, '0', true, ({toString:function(){return '0';}}), (function(){return 0;}), 1, (new Number(0)), false]); ");
/*fuzzSeed-248247344*/count=1218; tryItOut("mathy0 = (function(x, y) { return Math.atan((Math.pow(((Math.fround(-0) >= Math.fround(( ~ 2**53-2))) >>> 0), (Math.fround(Math.log10(Math.fround(( ~ (( ~ ((x << x) >>> 0)) | 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [2**53-2, -0x07fffffff, -0, 0x080000000, 0x100000001, 0/0, -0x100000000, 0x100000000, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 42, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, 0x080000001, 0, -0x080000000, Number.MAX_VALUE, 2**53+2, 2**53, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, 1.7976931348623157e308, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1219; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1.2089258196146292e+24;\n    var d3 = -6.044629098073146e+23;\n    var i4 = 0;\n    i0 = ((((i0)-((abs((~((0xffffffff))))|0) == (((-0x8000000)) & ((0x522f5d5c))))+(0x9645f5eb))>>>(((imul(((((0x10e03cb3))>>>((-0x8000000)))), (!((0x2845b2) <= (0xbf139db))))|0))+(/*FFI*/ff(((imul(((0x127efd4) ? (0x2922fbff) : (0xb1b20e14)), ((131073.0) > (-147573952589676410000.0)))|0)), (((-0xb2b5c*(0xfce7d55c)) ^ ((!(0x325ed39c))))))|0))) >= (0x6bb7152));\n    return +((+(0x62059361)));\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=1220; tryItOut("\"use strict\"; let(uofatd, [, ] =  /x/g .eval(\"27\"), b = a, {a: NaN} = -13, fpkiga, w = ({x: /\\b/ym}), d, x = \"\\u0114\", z, xtjqck) ((function(){with({}) throw StopIteration;})());");
/*fuzzSeed-248247344*/count=1221; tryItOut("f1 + this.f2;");
/*fuzzSeed-248247344*/count=1222; tryItOut("x.constructor;for(let y in /*PTHR*/(function() { for (var i of /*PTHR*/(function() { for (var i of allocationMarker()) { yield i; } })()) { yield i; } })()) let(__proto__ = this.__defineSetter__(\"e\", decodeURIComponent), e = (String.prototype.endsWith--), neqfkl, gqkjse, scufuw, get) ((function(){throw StopIteration;})());");
/*fuzzSeed-248247344*/count=1223; tryItOut("testMathyFunction(mathy3, [0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 0x100000001, Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, 2**53, -(2**53+2), -0x100000001, 0x100000000, 0x080000000, 0, 2**53-2, -0x080000001, -(2**53-2), 1, -0x100000000, -1/0, -0x080000000, -(2**53), 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-248247344*/count=1224; tryItOut("\"use strict\"; /*MXX2*/g2.g0.Object.isExtensible = t1;");
/*fuzzSeed-248247344*/count=1225; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ! (Math.min(((Math.atan(Math.fround(((( + Math.max(x, (Math.log10((x >>> 0)) >>> 0))) > ( + y)) | 0))) | 0) * Math.fround(( ~ y))), ((( - Math.atan(x)) != ( + ( + ( + x)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=1226; tryItOut("mathy4 = (function(x, y) { return (Math.acosh(( + (( + (Math.fround(Math.max(Math.fround(( ~ x)), Math.tan(((y <= x) >>> 0)))) ? mathy0(Math.hypot(x, x), 0x100000001) : ( + x))) > ( + Math.atan(( + Math.abs((Math.pow(y, y) | 0)))))))) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1227; tryItOut("\"use strict\"; \"use asm\"; selectforgc(o0);");
/*fuzzSeed-248247344*/count=1228; tryItOut("mathy3 = (function(x, y) { return Math.exp(Math.hypot(Math.imul(Math.atan2(Math.cbrt(0x0ffffffff), Math.fround(mathy2(Math.fround((Number.MIN_VALUE >> 0x080000000)), Math.fround(( - x))))), ( - ( + y))), Math.hypot(x, Math.max((Math.abs((x >>> 0)) >>> 0), ( + mathy2((x | 0), (( ! (y | 0)) | 0))))))); }); ");
/*fuzzSeed-248247344*/count=1229; tryItOut("x = this.f2;");
/*fuzzSeed-248247344*/count=1230; tryItOut("\"use strict\"; /*vLoop*/for (zwsstl = 0; zwsstl < 7; ++zwsstl) { var e = zwsstl; [1,,]; } ");
/*fuzzSeed-248247344*/count=1231; tryItOut("/*infloop*/L:for(let x in (window = \"\\uFCDD\")) {for(var c in ((null)(++b)))(void schedulegc(g1));/*RXUB*/var r = /\\cT\\b{3}.(?!^)|(?=[^][^]{2})+?{3}\\1{4,}(?=(?!(?:(?=\\d))))/ym; var s = \"\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav\\n\\na\\nava\\nava\\nava\\nav0\"; print(s.search(r)); print(r.lastIndex);  }");
/*fuzzSeed-248247344*/count=1232; tryItOut("a2 = g2.r1.exec(s0);");
/*fuzzSeed-248247344*/count=1233; tryItOut("\"use strict\"; for (var p in f1) { try { h1.iterate = (function() { g1.v0 = (this.g2 instanceof this.p0); return o2; }); } catch(e0) { } try { t2[12] = i0; } catch(e1) { } o0 = {}; }");
/*fuzzSeed-248247344*/count=1234; tryItOut("print(uneval(p1));function x(e, yield = (Math.PI), ...NaN)\"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var acos = stdlib.Math.acos;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 2305843009213694000.0;\n    var d3 = 2097151.0;\n    var d4 = 34359738369.0;\n    d3 = (d2);\n    return ((((((( /x/ ) ? ((((0x6088a070)) << ((0xffffffff))) > (~((0xffffffff)))) : ((0xfbf0c66b) ? (0xf8529ce4) : (0xf9fe202f)))+(0xfe69a3d0))|0))-((0x2ea1b9c4) ? (0xd79387a1) : (1))))|0;\n    {\n      d3 = (Infinity);\n    }\n    {\n      (Float32ArrayView[((0x7b0a025a)+((0xfda20905) ? (1) : ((0xffffffff) ? (0xfc418a6c) : (0xc6fb37)))) >> 2]) = ((d0));\n    }\n    d2 = (d4);\n    {\n      d0 = (+(0.0/0.0));\n    }\n    {\n      d1 = (d4);\n    }\n    d1 = (d3);\n    return ((-0xdf060*(!(0xe7890899))))|0;\n    {\n      {\n        (Float64ArrayView[((0x16c9643c)+((+abs(((+abs(((+((562949953421313.0))))))))) >= (-((+acos(((Float64ArrayView[4096])))))))) >> 3]) = ((Infinity));\n      }\n    }\n    d1 = (d0);\n    d2 = (-8388609.0);\n    d3 = (d0);\n    (Int16ArrayView[4096]) = ((0xfa7e73d4)*0xfb2fc);\n    {\n      (Float64ArrayView[0]) = ((d0));\n    }\n    d0 = (d0);\n    (Float64ArrayView[0]) = ((+(~((Uint16ArrayView[2])))));\n    {\n      d4 = (+(-1.0/0.0));\n    }\n    {\n      d3 = (1.0);\n    }\n    return (((0xc2d9e900)))|0;\n    return (((Float32ArrayView[2])))|0;\n  }\n  return f;(\"\\u51C5\");x = (4277);");
/*fuzzSeed-248247344*/count=1235; tryItOut("\"use strict\"; /*hhh*/function pbqwbj(d){s2.valueOf = (function() { try { (void schedulegc(g1)); } catch(e0) { } try { this.v0 = Object.prototype.isPrototypeOf.call(i0, o0.o2); } catch(e1) { } this.t2 = t2.subarray(x); return s2; });}pbqwbj();");
/*fuzzSeed-248247344*/count=1236; tryItOut("i2 = new Iterator(v1, true)\nprint(void  /x/g );");
/*fuzzSeed-248247344*/count=1237; tryItOut("m0.set(x, o1.g2.h0);");
/*fuzzSeed-248247344*/count=1238; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=1239; tryItOut("a2.pop(f0);");
/*fuzzSeed-248247344*/count=1240; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, -Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 1, 0x100000000, 2**53, -0x07fffffff, 2**53-2, -0x080000000, -0x100000001, 1/0, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 0, -Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, -0, -(2**53-2), -(2**53+2), 0.000000000000001, -(2**53), -0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1241; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ! (mathy0(Math.fround((Math.fround(Math.log10((0.000000000000001 >>> 0))) != (Math.fround(( + (x | 0))) | 0))), x) >>> 0)) ** ( ~ Math.fround((Math.fround(((((Math.cosh(x) | 0) - (-Number.MAX_VALUE >>> 0)) >= Math.fround(Math.log1p(((mathy0(0x100000001, Math.fround(y)) | 0) >>> 0)))) | 0)) ^ Math.fround(( + Math.acosh(( + ( + ( + y)))))))))); }); testMathyFunction(mathy2, [0x080000000, -(2**53), -0x0ffffffff, -(2**53+2), -1/0, -0x07fffffff, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 2**53-2, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, -0x100000000, 1, 0x080000001, 0, -0x080000000, Math.PI, -0x100000001, 0.000000000000001, 0x100000001, 1/0, 2**53, -Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-248247344*/count=1242; tryItOut("a1 = a1.slice(this.f1);");
/*fuzzSeed-248247344*/count=1243; tryItOut("mathy2 = (function(x, y) { return ((Math.atan2(Math.min(( + ( + ( + ( + (( + Math.min(x, x)) >= ( + ( + (y >>> 0)))))))), ((Math.asinh(((Math.fround(0x100000001) >= x) >>> 0)) !== ( - Math.hypot(-1/0, (x | 0)))) | 0)), ( - ((Math.imul((((y & ((y - 2**53+2) | 0)) >>> 0) >>> 0), ((x < ( + x)) >>> 0)) >>> 0) && (((Math.min(x, y) >>> (Math.pow(2**53, x) >>> 0)) >>> 0) >>> 0)))) && ((mathy0(Math.atan2(( + ( ! (mathy1(Math.pow(y, -(2**53+2)), x) >>> 0))), (( ! ((-0x080000000 | 0) >> y)) | 0)), ( + ( ~ mathy1((( + (y >>> 0)) >>> 0), (y >>> 0))))) | 0) | 0)) | 0); }); testMathyFunction(mathy2, [1/0, 0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, -0x080000001, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, -1/0, -0x080000000, -0, Math.PI, 0/0, 1, -0x100000000, 42, 0, Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-248247344*/count=1244; tryItOut("Array.prototype.pop.call(g1.a0);(([]));");
/*fuzzSeed-248247344*/count=1245; tryItOut("\"use strict\"; [];");
/*fuzzSeed-248247344*/count=1246; tryItOut("this.a2 = Array.prototype.slice.call(a1, -11, -3, a0);");
/*fuzzSeed-248247344*/count=1247; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( ! Math.fround(( - ( + (( + Math.sin(( ~ y))) ** (mathy1(mathy1(x, x), y) | 0))))))); }); testMathyFunction(mathy4, [-(2**53+2), -0x100000000, -0x100000001, 0x100000000, 1.7976931348623157e308, -0x0ffffffff, -0x07fffffff, 0.000000000000001, 0x080000000, 0x080000001, 1, -Number.MAX_VALUE, 0/0, Math.PI, 1/0, 0, 0x0ffffffff, 0x07fffffff, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x080000001, 42, 2**53-2, 2**53+2]); ");
/*fuzzSeed-248247344*/count=1248; tryItOut("\"use strict\"; t1 = t1[v1];");
/*fuzzSeed-248247344*/count=1249; tryItOut("/*MXX1*/o1 = g1.Object.getPrototypeOf;print(i0);");
/*fuzzSeed-248247344*/count=1250; tryItOut("testMathyFunction(mathy0, [0.000000000000001, 2**53, 0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -0x0ffffffff, 0x100000000, 42, Math.PI, 2**53-2, -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -(2**53+2), 1, -0x100000001, 1/0, -0x080000000, 0, Number.MAX_VALUE, 0/0, -0, -Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1251; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1252; tryItOut("a2[v1] = v1;");
/*fuzzSeed-248247344*/count=1253; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((0xd9863e52))+(-0x8000000)+(-0x8000000)))|0;\n    i1 = ((+(1.0/0.0)) <= (-((-9.44473296573929e+21))));\n    {\n      d0 = (d0);\n    }\n    d0 = (d0);\n    d0 = (9.44473296573929e+21);\n    i1 = (i1);\n    i1 = (x - (4277));\n    d0 = (d0);\n    i1 = (0xfffe1edd);\n    (Float32ArrayView[((0xfcabcb6b)) >> 2]) = ((NaN));\n    (Uint8ArrayView[((~~(((-1125899906842625.0)) / (((~((0xfb5107ed))))))) % (((((-3.777893186295716e+22)) % ((+atan2(((72057594037927940.0)), ((-8589934592.0))))))))) >> 0]) = ((0xe7629d54)+(-0x8000000));\n    {\n      i1 = (0xffffffff);\n    }\n    (Float32ArrayView[((/*FFI*/ff(((~(((0x242bf))))), ((-0.25)), ((((0xffffffff)+(0xea65129c)+(0xb8225afe)) << ((0x7776406)+(0xffffffff)-(0xffffffff)))), ((~~(-4.722366482869645e+21))), ((abs((0x7fffffff))|0)))|0)) >> 2]) = ((makeFinalizeObserver('tenured')));\n    return (((+(-0x26c21e9))))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0x080000000, 1, 2**53, 2**53-2, 42, Number.MAX_VALUE, -1/0, -0x080000000, -0x080000001, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 0/0, 2**53+2, 1/0, Math.PI, -0x0ffffffff, 0, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 0.000000000000001, 0x100000001, 0x0ffffffff, -0x100000000, 0x080000001, 0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-248247344*/count=1254; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.imul(Math.log(( + Math.fround(Math.fround(Math.acos(Math.fround(y)))))), ( ~ ( ! Math.sign((y * (Math.PI | y)))))), Math.hypot((Math.sin((( - (((( + ((Math.fround(x) ? Math.fround((y ? y : Math.fround(-Number.MIN_VALUE))) : Math.fround(x)) >>> 0)) ^ (Math.PI | 0)) | 0) >>> 0)) >>> 0)) | 0), (Math.imul(Math.fround(y), y) >>> 0))); }); testMathyFunction(mathy0, [42, -0x080000000, Math.PI, Number.MIN_VALUE, 2**53+2, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), 1/0, Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, -0, 1, 0x100000001, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, 2**53-2, 0x080000000, -0x0ffffffff, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1255; tryItOut("mathy2 = (function(x, y) { return ( - mathy1(( + Math.asin(( + ( ! ( + x))))), ( ~ (( + x) ? ( + ( + (( + Math.PI) % ( + y)))) : (y || Math.imul(y, -0)))))); }); testMathyFunction(mathy2, /*MARR*/[arguments,  'A' , [], x, x, arguments,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , arguments, [], arguments,  'A' ,  /x/ ]); ");
/*fuzzSeed-248247344*/count=1256; tryItOut("\"use strict\"; h1.__iterator__ = (function mcc_() { var puxvng = 0; return function() { ++puxvng; if (/*ICCD*/puxvng % 6 == 2) { dumpln('hit!'); b1 = t1.buffer; } else { dumpln('miss!'); try { i0.next(); } catch(e0) { } try { v2 = r0.multiline; } catch(e1) { } /*MXX2*/g2.Array.prototype.some = v0; } };})();");
/*fuzzSeed-248247344*/count=1257; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(t0, o0.s1);");
/*fuzzSeed-248247344*/count=1258; tryItOut("i2 = Proxy.create(h1, o1.f2);");
/*fuzzSeed-248247344*/count=1259; tryItOut("g1 = x;");
/*fuzzSeed-248247344*/count=1260; tryItOut(";");
/*fuzzSeed-248247344*/count=1261; tryItOut("\"use strict\"; a2.forEach(f0, (4277), true.unwatch(\"toLocaleString\"), o2);");
/*fuzzSeed-248247344*/count=1262; tryItOut("let (w) { a1.splice(-2, 5, g0.m2); }");
/*fuzzSeed-248247344*/count=1263; tryItOut("v1 = (this.a1 instanceof o2);");
/*fuzzSeed-248247344*/count=1264; tryItOut("return;(\"\\u63A3\");");
/*fuzzSeed-248247344*/count=1265; tryItOut("\"use strict\"; v2 = (i0 instanceof e1);const x = (4277).__defineGetter__(\"x\", WeakSet);");
/*fuzzSeed-248247344*/count=1266; tryItOut("\"use strict\"; this.g1.h2.getOwnPropertyNames = f1;");
/*fuzzSeed-248247344*/count=1267; tryItOut("with(new RegExp(\"($+|.)\", \"y\"))e0.has(e2);");
/*fuzzSeed-248247344*/count=1268; tryItOut("for(let x in []);");
/*fuzzSeed-248247344*/count=1269; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.cosh((Math.round((Math.hypot(x, Math.fround(( + Math.clz32(( + -1/0))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x080000001, 0, 0x080000000, 1/0, 0/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 2**53+2, -0x100000001, -(2**53), -0, 1, 0x100000000, 0x0ffffffff, 0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 2**53-2, -0x0ffffffff, -0x07fffffff, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, 42, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-248247344*/count=1270; tryItOut("\"use strict\"; e2.add(this.p0);");
/*fuzzSeed-248247344*/count=1271; tryItOut("/*bLoop*/for (let uhbdyd = 0; uhbdyd < 28; length, ++uhbdyd) { if (uhbdyd % 2 == 0) { print(/(?!.\\S[^\\D\\w\\u00F3-\u4003]*?)|(?:\\b+?\\b)/gim); } else { {}; }  } \nprint(i1);var z = a = x;");
/*fuzzSeed-248247344*/count=1272; tryItOut("\"use asm\"; a2.length = 9;function NaN()(4277)v1 = o0.g0.g1.eval(\"new Set()\");");
/*fuzzSeed-248247344*/count=1273; tryItOut("/*RXUB*/var r = r0; var s = s1; print(uneval(s.match(r))); ");
/*fuzzSeed-248247344*/count=1274; tryItOut("i1.toSource = (function() { for (var j=0;j<16;++j) { f2(j%2==1); } });");
/*fuzzSeed-248247344*/count=1275; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (mathy1(( + Math.fround((y | Math.fround(( - x))))), mathy1((mathy2(((Math.atanh(Math.fround(( + Math.hypot(( + ( ~ x)), ( + ( - x)))))) | 0) | 0), 2**53) | 0), (y , -0x0ffffffff))) ? Math.acosh((Math.fround(Math.max((( + ( ~ Math.pow(Math.imul(0x0ffffffff, (0x100000001 >>> 0)), x))) >>> 0), (Math.atanh(( + x)) >>> 0))) >>> 0)) : ( + ((Math.log(Math.fround(( ~ (y >>> 0)))) ** Math.fround(Math.max(Math.fround((( - (Math.imul(Math.atan2(x, (((x | 0) ? (x | 0) : (y | 0)) | 0)), y) >>> 0)) >>> 0)), (2**53 | 0)))) | 0)))); }); testMathyFunction(mathy4, [2**53+2, -1/0, 1, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 0, -(2**53+2), Number.MAX_VALUE, 1/0, Math.PI, 0x100000001, 2**53, -(2**53-2), 0x080000001, -0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 0x100000000, 0x0ffffffff, 2**53-2, -0x07fffffff, 0/0, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, -0, -(2**53), 42, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1276; tryItOut("h2.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-248247344*/count=1277; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return (((Math.imul(( + ( ~ y)), -0x100000000) | Math.fround(Math.pow(( + ((mathy0(((Math.sinh((x - 0x100000000)) >>> 0) | 0), (y | 0)) | 0) - ( + (Math.imul((x >>> 0), (-0x0ffffffff >>> 0)) >>> 0)))), Math.fround((Math.min((2**53-2 | 0), x) >>> 0))))) >>> 0) <= (( ~ (( + ( + mathy0(( ! y), x))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-248247344*/count=1278; tryItOut("e2.has(g0);");
/*fuzzSeed-248247344*/count=1279; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (mathy2((Math.min(( ~ mathy1(Math.fround(Math.cbrt(Math.fround((-0x080000001 !== x)))), mathy4(x, x))), (((( + Math.cos((x | 0))) ? (y | 0) : (Math.trunc(( + x)) | 0)) | 0) >>> 0)) >>> 0), ((((Math.min((-0x07fffffff | 0), Math.atanh(( + (((0x080000000 % (y / y)) >>> 0) & (((x ^ (y >>> 0)) >>> 0) >>> 0))))) | 0) - ((Math.min(((( ! mathy1(Math.imul((x >>> 0), x), x)) >>> 0) >>> 0), (0x0ffffffff >>> 0)) >>> 0) | 0)) | 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1280; tryItOut("print(x);function arguments[\"apply\"](\u000ce = \"\\u5B21\", eval = new RegExp(\"(?=(.{2147483647,})*|\\\\x46)\", \"yim\"))(/*UUV1*/(e.getUTCSeconds = WeakSet.prototype.add))(-29);");
/*fuzzSeed-248247344*/count=1281; tryItOut(";");
/*fuzzSeed-248247344*/count=1282; tryItOut("this.a2 = arguments.callee.caller.arguments;function w()\"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.00390625;\n    var d3 = -590295810358705700000.0;\n    var i4 = 0;\n    i4 = (((!(0xfb1f67eb)) ? ((d2) + (Infinity)) : (d3)) == (+atan2(((1.9342813113834067e+25)), ((+pow(((+(-1.0/0.0))), ((((d2)) / ((d3))))))))));\n    {\n      d3 = (d3);\n    }\n    {\n      d2 = (d2);\n    }\n    d3 = ((((((0xeb006895)-(1))|0) / (0x4f48368d)) >> (0x154a9*(0xccc6224c))));\n    d2 = (((+(((0xffffffff)-((((0xd8fa21f1))>>>((0xfed6bebb))) != (0x6c487c5e))-((((0xffffffff))>>>((0x7d4862bb)))))>>>(((d2) > (((+(0x7fffffff))) % ((d1)))))))) / (((((imul((-0x8000000), (-0x1cfdaef))|0)))|0)));\n    (Uint8ArrayView[((0xf8b5515a)) >> 0]) = (-((0x4253e7b0)));\n    d0 = ((let (d) (e <= NaN)));\n    return ((((0x0) < (0x7b000d32))-(0xff6488ed)))|0;\n  }\n  return f;e2.delete(h0);");
/*fuzzSeed-248247344*/count=1283; tryItOut("/*iii*/a0.valueOf = (function() { try { Array.prototype.sort.call(o1.a0, (function() { for (var j=0;j<2;++j) { f2(j%4==0); } })); } catch(e0) { } m1.delete(g2); return f2; });/*hhh*/function xuihuw(\u3056, x, c = eval(\"mathy0 = (function(x, y) { return (( + (( + ( + Math.exp(( + ( ! (y != 0x07fffffff)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[new Number(1),  '' , \\\"\\\\u5DEB\\\", new Number(1), \\\"\\\\u5DEB\\\", \\\"\\\\u5DEB\\\", \\\"\\\\u5DEB\\\", \\\"\\\\u5DEB\\\", \\\"\\\\u5DEB\\\", \\\"\\\\u5DEB\\\", (void 0), (1/0),  '' , \\\"\\\\u5DEB\\\", new Number(1), (1/0)]); \"), c, c, NaN, Uint8ClampedArray.prototype.constructor, \u3056, x, NaN, eval, x, x = x, d, x, NaN, y, x, x, x, window = new RegExp(\"(?=$\\\\\\ue465|\\\\D+?)(?!.)|.|(?:(?:[^]))+?(?!^)[^]\", \"yim\"), d, z, x, \u3056 =  /x/ , e, eval = this, x, NaN =  /x/g , eval, b, a, a =  \"\" , a, window, eval, x = new RegExp(\"(?:(?:\\\\S|^\\\\d))\\\\3+?\\u008a{2}((?=[^\\\\ub1a5--\\\\x0F]|\\\\\\u0001))|.|\\\\3*?+\", \"m\"), eval, x, x, x =  \"\" , x, x, e = 9, x, NaN =  \"\" , x, a, x, \u3056 = \"\\uB938\", y, window, c, \u3056, w){print(x);}");
/*fuzzSeed-248247344*/count=1284; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (Infinity);\n    {\n      d1 = (((-8193.0)) - ((((((0x7fffffff) % (0x37b71fde))|0) == (imul((i0), ((0x4626c491) == (0xe72611ac)))|0)) ? (+pow(((d1)), ((16777217.0)))) : (+abs((((((-1125899906842625.0)) - ((2.3611832414348226e+21))) + (d1))))))));\n    }\n    d1 = (d1);\n    return +((137438953473.0));\n    i0 = (0x1db61abd);\n    d1 = (+(1.0/0.0));\n    d1 = (-4096.0);\n    (Int16ArrayView[(window) >> 1]) = ((i0));\n    d1 = (d1);\n    d1 = ((0x5a0af2e3) ? (+(0.0/0.0)) : (d1));\n    return +(((((d1))) + (((+(0.0/0.0))) % ((+(0.0/0.0))))));\n    (Float32ArrayView[(((~((~~(-524289.0)) % (~((0xb68d5d75))))))*-0xaf281) >> 2]) = ((Float64ArrayView[4096]));\n    i0 = ((~((/*FFI*/ff()|0))));\n    return +((+((+(-1.0/0.0)))));\n  }\n  return f; })(this, {ff: (\u3056) =>  { yield this ?  \"\"  : ({}) } }, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=1285; tryItOut("p1.toString = (function() { try { t2 = new Uint32Array(b2); } catch(e0) { } try { h0.delete = (function() { h2.getOwnPropertyDescriptor = f1; return b0; }); } catch(e1) { } try { v2 = o2.a1.length; } catch(e2) { } for (var p in i1) { g0.offThreadCompileScript(\"/*infloop*/L:for(e = ((makeFinalizeObserver('nursery'))); undefined; new -25((z = [1,,]), false)) {f2 + h1;Object.preventExtensions(t0); }\"); } return m1; });");
/*fuzzSeed-248247344*/count=1286; tryItOut("((runOffThreadScript)(Math.imul( '' ,  '' )\u0009));");
/*fuzzSeed-248247344*/count=1287; tryItOut("( /x/g );");
/*fuzzSeed-248247344*/count=1288; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.max(( + Math.acos(( + Math.fround(((( + x) | 0) & ( - Math.fround(mathy2(x, Math.fround(mathy2(y, Math.fround(((x | 0) ** x)))))))))))), ((( ! Math.atan2(x, (((x >>> 0) / (-(2**53-2) >>> 0)) >>> 0))) >> (mathy1((y >>> 0), ((x === x) >>> 0)) >>> 0)) & Math.fround((Math.fround(x) < ((((y | 0) && ((Math.imul((2**53+2 >>> 0), y) >>> 0) | 0)) | 0) | 0))))) >>> 0); }); testMathyFunction(mathy3, [null, (new Number(-0)), 0, ({valueOf:function(){return 0;}}), '', [0], undefined, [], -0, /0/, ({toString:function(){return '0';}}), (new String('')), (new Boolean(true)), false, objectEmulatingUndefined(), (new Boolean(false)), 1, NaN, (function(){return 0;}), '\\0', ({valueOf:function(){return '0';}}), true, '0', (new Number(0)), '/0/', 0.1]); ");
/*fuzzSeed-248247344*/count=1289; tryItOut("v0 = r2.multiline;");
/*fuzzSeed-248247344*/count=1290; tryItOut("mathy0 = (function(x, y) { return (( + ((Math.pow(Math.fround((((( + y) >= y) % Math.hypot(intern(-18), x)) >>> 0)), ((( + Math.ceil(Math.pow(0x100000000, x))) + ((( + ( ! -0x080000000)) <= ( + (-(2**53-2) ? x : y))) >>> 0)) >>> 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy0, [0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0, 0x100000000, Number.MAX_VALUE, -(2**53), -0x100000000, -0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0.000000000000001, 2**53+2, Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), -Number.MIN_VALUE, 0x100000001, 0x080000001, -0x100000001, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, -1/0, 1/0, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1291; tryItOut("/* no regression tests found */\nv2 = -Infinity;\n");
/*fuzzSeed-248247344*/count=1292; tryItOut("testMathyFunction(mathy0, [0.000000000000001, 1/0, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53, 1, Math.PI, -1/0, 0x080000000, -0x07fffffff, 0, -0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, -(2**53-2), 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -(2**53), -0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -(2**53+2), Number.MIN_VALUE, 1.7976931348623157e308, 42, -Number.MAX_VALUE, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1293; tryItOut("\"use strict\"; a0 = this.a1.slice(-19, NaN, v2);");
/*fuzzSeed-248247344*/count=1294; tryItOut("neuter(b0, \"same-data\");");
/*fuzzSeed-248247344*/count=1295; tryItOut("(undefined);\n /x/ ;\n");
/*fuzzSeed-248247344*/count=1296; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-248247344*/count=1297; tryItOut("\"use strict\"; ;");
/*fuzzSeed-248247344*/count=1298; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-(2**53-2), Math.PI, 0x080000000, 0x080000001, 0x0ffffffff, 1.7976931348623157e308, -0, 0.000000000000001, 0/0, 42, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 1/0, -(2**53), -0x100000000, -(2**53+2), 2**53, 0, Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, -0x080000000, 2**53+2, -Number.MAX_VALUE, 0x100000000, -0x100000001]); ");
/*fuzzSeed-248247344*/count=1299; tryItOut("t0 + '';");
/*fuzzSeed-248247344*/count=1300; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.cos(mathy2((x >>> 0), ((Math.sqrt(Math.fround(y)) >>> 0) << mathy1(Math.acos(x), x)))), Math.pow(((Math.ceil((Math.pow(Math.PI, Math.acos(y)) | 0)) | 0) | 0), Math.fround(( + ( ~ ( + ( + (x + (x >>> y))))))))); }); ");
/*fuzzSeed-248247344*/count=1301; tryItOut("\"use strict\"; print(f1);");
/*fuzzSeed-248247344*/count=1302; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1303; tryItOut("testMathyFunction(mathy3, ['/0/', false, undefined, true, objectEmulatingUndefined(), 0.1, NaN, (new Number(-0)), (new Boolean(false)), (new Boolean(true)), 0, -0, '\\0', (new Number(0)), [], (new String('')), ({toString:function(){return '0';}}), [0], 1, null, '0', ({valueOf:function(){return '0';}}), '', /0/, (function(){return 0;}), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-248247344*/count=1304; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.sign((( ~ (Math.asinh(( + y)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-(2**53+2), 1/0, Number.MIN_VALUE, -0x080000000, 0x100000001, -1/0, -0x0ffffffff, 2**53, -Number.MIN_VALUE, -(2**53-2), 0x080000000, 0x07fffffff, 0x100000000, Number.MAX_VALUE, 0, 42, 0.000000000000001, 0/0, -0, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, -0x07fffffff, -0x080000001, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2]); ");
/*fuzzSeed-248247344*/count=1305; tryItOut("v1 = false;");
/*fuzzSeed-248247344*/count=1306; tryItOut("mathy2 = (function(x, y) { return (Math.sqrt(Math.fround((Math.fround(Math.log2(( + Math.round((y >>> 0))))) >>> Math.fround((((x | 0) % ((mathy0(x, x) * x) | 0)) | 0))))) | 0); }); testMathyFunction(mathy2, [Math.PI, 0, -0x080000000, 1, -Number.MIN_VALUE, -0x100000001, 0x07fffffff, -0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, 42, -1/0, 0.000000000000001, Number.MAX_VALUE, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 0x100000001, Number.MIN_VALUE, 2**53, -(2**53+2), -(2**53-2), 1/0, -0, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1307; tryItOut("\"use strict\"; h1 = g2.objectEmulatingUndefined();");
/*fuzzSeed-248247344*/count=1308; tryItOut("mathy1 = (function(x, y) { return (Math.fround((Math.fround(Math.pow(Math.atan2(((((mathy0(Math.fround(1/0), Math.fround(-0x100000000)) | 0) >>> 0) - ( + y)) >>> 0), Math.fround((Math.fround(Math.imul(y, 2**53-2)) != Math.fround(y)))), Math.fround(Math.sqrt(Math.fround((( ! (Math.fround(Math.pow(x, Math.fround(y))) >>> 0)) >>> 0)))))) , Math.fround((Math.cos((Math.hypot(x, Number.MIN_SAFE_INTEGER) | 0)) | 0)))) >= (Math.max((Math.hypot((Math.imul((((2**53 >>> 0) == (y >>> 0)) >>> 0), y) | 0), (Math.min(y, 0x0ffffffff) | 0)) >>> 0), (Math.acos(( ~ ( + ( + ((Math.atan2((mathy0(y, x) | 0), (0/0 | 0)) | 0) | 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [NaN, null, (new Number(-0)), 0.1, objectEmulatingUndefined(), 0, [0], '0', ({toString:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Number(0)), 1, '/0/', '', undefined, true, (new String('')), -0, [], false, (new Boolean(false)), /0/, (new Boolean(true)), '\\0', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-248247344*/count=1309; tryItOut("");
/*fuzzSeed-248247344*/count=1310; tryItOut("new RegExp(\".\", \"\");");
/*fuzzSeed-248247344*/count=1311; tryItOut("mathy4 = (function(x, y) { return ( - Math.hypot(mathy2((Math.fround(mathy3(x, Math.ceil(x))) | (Math.asin(42) >>> 0)), ( + mathy0((((-Number.MAX_SAFE_INTEGER >>> 0) ^ (y >>> 0)) >>> 0), ( - ( + (Math.max(y, (y >>> 0)) >>> 0)))))), (Math.imul((Math.min((Math.fround((y <= Math.cbrt(y))) | 0), (Math.cbrt((x >>> 0)) >>> 0)) | 0), Math.fround(mathy1(Math.fround(y), Math.fround(( + (((y < y) >>> 0) ^ ( ! ( + (y > y))))))))) | 0))); }); testMathyFunction(mathy4, [-0x100000001, 0x100000000, -0x0ffffffff, 0x100000001, 2**53-2, Math.PI, 2**53+2, -0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -(2**53), 0x080000000, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, Number.MAX_VALUE, 1, -0x080000000, Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, 42, 1/0, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1312; tryItOut("v0 = g0.eval(\"function f1(e2) \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    (Float64ArrayView[(((0xd1e15134) != (0xac444e96))*-0x42e7b) >> 3]) = ((Float32ArrayView[0]));\\n    return (((imul((((0x8fa55*((Float64ArrayView[2]))))), ((0xdcc15f10)))|0) % (((-0x8000000)) ^ (((((~~(+(1.0/0.0))))|0))-(0xfa41f812)+(0xf872d59e)))))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-248247344*/count=1313; tryItOut("{ void 0; gcslice(91766); } print(x);");
/*fuzzSeed-248247344*/count=1314; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy2(Math.min(( ! ( + mathy0(Math.fround(Math.fround(Math.fround(1/0))), Math.atan(y)))), Math.log((mathy0(Math.cos((Number.MAX_VALUE | 0)), x) | 0))), (Math.hypot(Math.fround(mathy1(y, Math.ceil(x))), Math.fround(( + ( ! (( + ( + (mathy0(y, (x >>> 0)) >>> 0))) >>> 0))))) >>> 0)); }); testMathyFunction(mathy3, ['', '\\0', (new Number(0)), 0.1, '0', (new Boolean(false)), null, (new Number(-0)), 0, undefined, 1, true, (function(){return 0;}), objectEmulatingUndefined(), false, (new String('')), /0/, -0, [0], ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Boolean(true)), ({toString:function(){return '0';}}), NaN, [], '/0/']); ");
/*fuzzSeed-248247344*/count=1315; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return (Math.hypot(((( - Math.imul(x, Math.fround(y))) | 0) >>> 0), ((((Math.max((mathy0(((Math.fround(x) === (Math.hypot((x | 0), y) % x)) >>> 0), Math.fround(y)) >>> 0), x) | 0) >= ( + (mathy1((Math.log10(( + mathy1((y >>> 0), ( + -1/0)))) | 0), y) <= (Math.sign(((Math.sign(Math.pow((1 | 0), (x | 0))) == (0/0 >>> 0)) >>> 0)) | 0)))) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, 2**53-2, -0x100000000, -(2**53+2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0x080000000, Number.MAX_VALUE, 0x100000001, -0x0ffffffff, 2**53, 1, -0x07fffffff, 1/0, 0x07fffffff, -0, 0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 0x100000000, -(2**53), 0, 0x0ffffffff, 0/0, 2**53+2, 42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=1316; tryItOut("a0[5] = /\\1{0}/g;");
/*fuzzSeed-248247344*/count=1317; tryItOut("for (var p in m2) { s0 = new String; }");
/*fuzzSeed-248247344*/count=1318; tryItOut("\"use strict\"; var dxvltb = new ArrayBuffer(8); var dxvltb_0 = new Int32Array(dxvltb); dxvltb_0[0] = -9; var dxvltb_1 = new Int8Array(dxvltb); print(dxvltb_1[0]); dxvltb_1[0] = 23; var dxvltb_2 = new Float32Array(dxvltb); dxvltb_2[0] = 7; var dxvltb_3 = new Uint8ClampedArray(dxvltb); dxvltb_3[0] = 0; var dxvltb_4 = new Uint32Array(dxvltb); dxvltb_4[0] = 1495514005.5; var dxvltb_5 = new Float64Array(dxvltb); dxvltb_5[0] = 22; var dxvltb_6 = new Int32Array(dxvltb); dxvltb_6[0] = -26; var dxvltb_7 = new Uint16Array(dxvltb); dxvltb_7[0] = 27; var dxvltb_8 = new Int8Array(dxvltb); dxvltb_8[0] = 3; throw (4277);yield (offThreadCompileScript)(/(\\2{0,}){2,4}|^/yim, \"\\uE26E\").__defineGetter__(\"dxvltb_4\", ((let (e=eval) e)).call)\n;/*RXUB*/var r = /^?|(?:((?=.)|.\\w{0,}\\1)*)\\1/g; var s = \"\\n\"; print(s.search(r)); for (var v of i1) { try { a0 + ''; } catch(e0) { } try { a1.reverse(); } catch(e1) { } g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (4277), noScriptRval: (dxvltb_5[5] % 2 == 1), sourceIsLazy: (dxvltb_8[0] % 47 != 1), catchTermination: (dxvltb_2 % 2 != 1) })); }");
/*fuzzSeed-248247344*/count=1319; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[ 'A' , function(){}, (void 0)]) { a1 = []; }");
/*fuzzSeed-248247344*/count=1320; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\3+?)*?{4294967297,}\", \"gyim\"); var s = \"\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\\u0098\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1321; tryItOut("var imxpgp = new SharedArrayBuffer(4); var imxpgp_0 = new Uint8Array(imxpgp); imxpgp_0[0] = 24; m0 = new Map(p0);");
/*fuzzSeed-248247344*/count=1322; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( - Math.fround((Math.fround((Math.fround(( + (( + Math.fround(( ! (y | 0)))) === ( + x)))) , Math.fround(Math.fround((Math.fround(((Math.fround(Math.max((1 | 0), 0x07fffffff)) ? (x >>> 0) : (x >>> 0)) >>> 0)) >>> Math.fround(Math.hypot((2**53-2 >>> 0), y))))))) != (((((x ? (y >>> 0) : ( ~ ( + Math.acosh(( + Math.hypot(x, x)))))) | 0) / (((( + (( + x) / ( + y))) | 0) ? (Math.round(x) | 0) : x) | 0)) | 0) | 0)))) >>> 0); }); testMathyFunction(mathy2, [0/0, -(2**53+2), Math.PI, -(2**53), 0x100000000, 1, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0x100000001, 0, -1/0, 0x080000001, -0x080000001, -0x080000000, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -0x100000000, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, 1/0]); ");
/*fuzzSeed-248247344*/count=1323; tryItOut("a0 = (4277);");
/*fuzzSeed-248247344*/count=1324; tryItOut("\"use strict\"; e = x;this.x = d;if(true) yield; else  if \u0009( /x/ .unwatch(\"toLocaleLowerCase\")) {e0 = new Set;m0.get(g2.o2); } else {v2 = o1.r1.multiline;o1.g2.toString = f2; }");
/*fuzzSeed-248247344*/count=1325; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=1326; tryItOut("a = Math.max( /x/g , \"\\uD258\");t2.set(o0.t2, 15);");
/*fuzzSeed-248247344*/count=1327; tryItOut("\"use strict\"; \"use asm\"; while((this) && 0)i0.next();");
/*fuzzSeed-248247344*/count=1328; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.clz32((Math.fround((Math.fround(0x080000001) ? Math.fround(mathy3((Math.fround(( ! -Number.MAX_VALUE)) ^ (-0 >>> 0)), x)) : Math.fround((mathy4(((mathy1((y | 0), Math.fround(( + Math.log(( + y))))) | 0) >>> 0), (Math.fround(( ! Math.fround(y))) >>> 0)) >>> 0)))) >>> (Math.fround(x) === ((Math.fround(y) ** (Math.cosh(y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-(2**53+2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, 0x0ffffffff, 1/0, 0x100000000, 0x080000000, 2**53, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 42, -(2**53), 1.7976931348623157e308, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0/0, 0, -Number.MIN_VALUE, 0x07fffffff, -0x100000001, -0x0ffffffff, Math.PI, 2**53-2, -0x080000001, 1, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1329; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan2((( + (( + (x >= y)) ? Math.pow(y, Math.fround(x)) : x)) >>> 0), Math.fround(Math.fround((Math.fround((Math.cbrt((y | 0)) >>> 0)) == (Math.min(Math.min(Math.hypot(y, -Number.MIN_VALUE), ((0.000000000000001 >>> 0) & (x >>> 0))), (( ~ y) >>> 0)) | 0))))) | ( - Math.fround(( - y)))); }); testMathyFunction(mathy0, [(function(){return 0;}), '/0/', (new Number(0)), '\\0', 0.1, (new Boolean(true)), '', -0, false, objectEmulatingUndefined(), (new String('')), ({toString:function(){return '0';}}), /0/, (new Boolean(false)), [0], (new Number(-0)), '0', 0, null, 1, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), [], NaN, undefined, true]); ");
/*fuzzSeed-248247344*/count=1330; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1331; tryItOut("mathy5 = (function(x, y) { return (mathy4(( + ((( + ((Math.tan(( + (x , y))) ? ( - Math.fround(x)) : Math.fround(( ~ x))) >>> 0)) >>> 0) & Math.hypot(Math.fround((y ? Math.log1p(Math.fround(( ! (y | 0)))) : y)), -(2**53)))), Math.pow(( + mathy0(y, ( + Math.fround(Math.atanh(Math.fround((y <= y))))))), ( + (Math.sqrt(Math.imul(x, y)) >>> 0)))) || ( - (Math.fround(mathy0(( - (( + Math.expm1((x >>> 0))) >>> 0)), ((Math.fround(0x100000001) || (0x080000000 === y)) >>> 0))) * Math.fround(Math.sign((((y >>> 0) != (1.7976931348623157e308 >>> 0)) + ( + ( ! ( + ( + ((y >>> 0) ? 0x080000001 : ( + y)))))))))))); }); testMathyFunction(mathy5, ['', 0, (new Boolean(false)), (function(){return 0;}), 0.1, /0/, [0], [], '0', objectEmulatingUndefined(), (new Boolean(true)), '\\0', (new Number(0)), '/0/', true, undefined, -0, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), NaN, ({valueOf:function(){return '0';}}), (new Number(-0)), (new String('')), null, 1, false]); ");
/*fuzzSeed-248247344*/count=1332; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    return (((i1)-((i0) ? (i1) : (!((274877906944.0) < (34359738369.0))))+((((4277).__defineGetter__(\"x\", runOffThreadScript))|0) == (((i0)-(!(0x7f39dc13))-(!(i0))) >> ((eval)\u000c(EvalError()))))))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[new String(''), new String(''), new String(''), new String(''), undefined, new String(''), undefined, undefined, new String(''), new String(''), new String(''), new String(''), new String('')]); ");
/*fuzzSeed-248247344*/count=1333; tryItOut("x = linkedList(x, 5859);");
/*fuzzSeed-248247344*/count=1334; tryItOut("\"use strict\"; /*oLoop*/for (var mwopyp = 0; mwopyp < 2; ++mwopyp) { print(x); } ");
/*fuzzSeed-248247344*/count=1335; tryItOut("mathy2 = (function(x, y) { return (Math.atanh(Math.fround((mathy1((((Math.fround(( ~ Math.fround(Number.MIN_SAFE_INTEGER))) | 0) && ((Math.atan2((x | 0), (-0x100000000 | 0)) | 0) | 0)) | 0), y) >>> 0))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[this, Infinity, NaN, NaN, Infinity, this, new Number(1), -0x07fffffff, new Number(1), this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, -0x07fffffff, new Number(1), Infinity, -0x07fffffff, new Number(1)]); ");
/*fuzzSeed-248247344*/count=1336; tryItOut("\"use strict\"; M:for([d, y] = (void shapeOf(/(?:(?:\u5798)|(?:\\D[^]|\\B)|\\b{4,})/yi)) in \"\\u0B03\") h2.fix = f0;");
/*fuzzSeed-248247344*/count=1337; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-248247344*/count=1338; tryItOut("/*ODP-1*/Object.defineProperty(m2, \"toSource\", ({configurable: false}));");
/*fuzzSeed-248247344*/count=1339; tryItOut("\"use strict\"; /*bLoop*/for (let bscgoh = 0; bscgoh < 55;  \"\" , function ([y]) { }, ++bscgoh) { if (bscgoh % 26 == 13) { print(x); } else { s0 += this.s0; }  } ");
/*fuzzSeed-248247344*/count=1340; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x07fffffff, 2**53-2, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 42, -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -1/0, 1, 2**53, 0.000000000000001, -(2**53-2), 1.7976931348623157e308, 0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 0x080000001, 0x100000001, 0/0, 0, 0x100000000, -Number.MIN_VALUE, -(2**53), 2**53+2, Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-248247344*/count=1341; tryItOut("print([function ([y]) { }]);");
/*fuzzSeed-248247344*/count=1342; tryItOut("\"use strict\"; Object.defineProperty(o1, \"v2\", { configurable: (x % 27 != 16), enumerable: new RegExp(\"\\\\1*?|.\", \"im\"),  get: function() {  return a2.length; } });");
/*fuzzSeed-248247344*/count=1343; tryItOut(" for  each(var b in ({x, this.zzz.zzz} = (([]) =  /x/  += x).eval(\"((eval)())\"))) g0 = this;");
/*fuzzSeed-248247344*/count=1344; tryItOut("\"use strict\"; this.t2.set(t1, v1);");
/*fuzzSeed-248247344*/count=1345; tryItOut("\"use strict\"; throw -11;this;");
/*fuzzSeed-248247344*/count=1346; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(b0, p1);");
/*fuzzSeed-248247344*/count=1347; tryItOut("Array.prototype.unshift.apply(a1, [o1, t2, e0, b0]);");
/*fuzzSeed-248247344*/count=1348; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { v1 = Object.prototype.isPrototypeOf.call(this.o0, this.m0);; var desc = Object.getOwnPropertyDescriptor(g0.a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v1 = (e2 instanceof t0);; var desc = Object.getPropertyDescriptor(g0.a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e0.delete(x);; Object.defineProperty(g0.a0, name, desc); }, getOwnPropertyNames: function() { h2.getOwnPropertyDescriptor = f2;; return Object.getOwnPropertyNames(g0.a0); }, delete: function(name) { r0 = /\\2{2,2}/gy;; return delete g0.a0[name]; }, fix: function() { ;; if (Object.isFrozen(g0.a0)) { return Object.getOwnProperties(g0.a0); } }, has: function(name) { g1.a2 = new Array;; return name in g0.a0; }, hasOwn: function(name) { v2 = Object.prototype.isPrototypeOf.call(g0.h1, m1);; return Object.prototype.hasOwnProperty.call(g0.a0, name); }, get: function(receiver, name) { f2(m2);; return g0.a0[name]; }, set: function(receiver, name, val) { o1.s1 += s1;; g0.a0[name] = val; return true; }, iterate: function() { i1.__iterator__ = f0;; return (function() { for (var name in g0.a0) { yield name; } })(); }, enumerate: function() { v2 = (this.i1 instanceof b0);; var result = []; for (var name in g0.a0) { result.push(name); }; return result; }, keys: function() { let v0 = a2.length;; return Object.keys(g0.a0); } });");
/*fuzzSeed-248247344*/count=1349; tryItOut("mathy1 = (function(x, y) { return (Math.fround(((((Math.abs((x != (( + (-(2**53+2) | 0)) >>> 0))) | 0) | 0) < (Math.acosh(0x080000000) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy1, [0x100000000, -(2**53-2), 1/0, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0, -0x07fffffff, 0/0, -0x100000000, 0x080000001, 42, Number.MIN_VALUE, 1, 2**53+2, 0, 2**53-2, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53), -0x080000000, 0x080000000, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1350; tryItOut("/*tLoop*/for (let d of /*MARR*/[arguments.callee, new Boolean(true), new Number(1.5), new Number(1.5), arguments.callee]) { /*oLoop*/for (qajjrz = 0; qajjrz < 3; ++qajjrz) { print(new RegExp(\"(?:(?=(?:(?=([^])))){1,})\", \"yi\")); }  }");
/*fuzzSeed-248247344*/count=1351; tryItOut("a0.unshift(m1);");
/*fuzzSeed-248247344*/count=1352; tryItOut("/*oLoop*/for (vvfhsz = 0; vvfhsz < 20; ++vvfhsz) { /*RXUB*/var r = new RegExp(\"(?!\\\\1)|(?:(?=\\\\W*?)${0,4}{4}){4}|\\\\S[^]{3}\", \"y\"); var s = \"000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n_000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n_000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n_000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n_000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n000\\n\\n\\n\\n_000\\n\\n\\n\\n000\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(r.test(s));  } ");
/*fuzzSeed-248247344*/count=1353; tryItOut("\"use strict\"; o0.a0.forEach((function() { try { e2.has(s2); } catch(e0) { } Object.defineProperty(this, \"r2\", { configurable: true, enumerable: (4277),  get: function() {  return new RegExp(\"\\\\2\", \"im\"); } }); return o0; }), e0);");
/*fuzzSeed-248247344*/count=1354; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((((((Math.fround(42) ** Math.fround(( + Math.fround((Math.min((y | 0), (Math.hypot(Math.fround(x), Math.fround(y)) | 0)) | 0))))) >>> 0) ^ ( + mathy0((x ** ( + ( + Math.sinh((y | 0))))), -0x100000001))) >>> 0) ? ( + Math.round(( + Math.log2(-0x07fffffff)))) : (mathy0(mathy1(((Math.pow((( ~ 0.000000000000001) >>> 0), (y >>> 0)) >>> 0) >>> 0), x), (Math.acos(/*wrap3*/(function(){ var ndwurr = -12.watch(\u3056, function(y) { print(0); }); (Function)(); })) | 0)) | 0)) >>> 0) != ( + (Math.log10((Math.pow(y, Math.imul(Math.atanh(x), Math.sign((5 >>> 0)))) | 0)) | 0))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 42, -0x100000001, -(2**53), 2**53+2, -0x100000000, -(2**53-2), -0x080000001, -0x07fffffff, -(2**53+2), -0x0ffffffff, 0x080000000, 1, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, 1/0, -0, 0x080000001, 0, 0/0, 0x100000000, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -1/0, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 2**53]); ");
/*fuzzSeed-248247344*/count=1355; tryItOut("\"use strict\"; Array.prototype.splice.apply(a2, [-5, 4]);");
/*fuzzSeed-248247344*/count=1356; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.pow(( + (( + ( ! y)) ** Math.fround((( ~ Math.pow(y, (Math.log1p(y) >>> 0))) | 0)))), (( ~ (Math.acosh((Math.cos(2**53) | 0)) | 0)) !== ((( + Math.hypot(Math.fround(( + Math.acosh((Math.hypot(x, y) >>> 0)))), Math.fround(x))) && ( + Math.max(Math.fround(( + (( + ( ! ( + x))) == x))), Math.fround(Math.sinh(x))))) >>> 0))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 0x100000001, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 1/0, -0x100000000, -Number.MAX_VALUE, 42, -0, 0/0, 0x100000000, -0x080000001, -(2**53), 1, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, 0, 0x07fffffff, Math.PI, 2**53, 0.000000000000001, 0x080000000, -(2**53+2), -0x0ffffffff, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1357; tryItOut("var dkwjyk = new ArrayBuffer(0); var dkwjyk_0 = new Uint16Array(dkwjyk); var dkwjyk_1 = new Uint16Array(dkwjyk); print(dkwjyk_1[0]); dkwjyk_1[0] = -22; var dkwjyk_2 = new Uint8Array(dkwjyk); dkwjyk_2[0] = 23; var dkwjyk_3 = new Uint8ClampedArray(dkwjyk); var dkwjyk_4 = new Uint16Array(dkwjyk); var dkwjyk_5 = new Uint8ClampedArray(dkwjyk); print(dkwjyk_5[0]); dkwjyk_5[0] = 8; var dkwjyk_6 = new Uint32Array(dkwjyk); var dkwjyk_7 = new Uint16Array(dkwjyk); print(dkwjyk_7[0]); dkwjyk_7[0] = 20; var dkwjyk_8 = new Uint16Array(dkwjyk); print(dkwjyk_8[0]); dkwjyk_8[0] = 26; var dkwjyk_9 = new Uint16Array(dkwjyk); h2.toSource = (function(stdlib, foreign, heap){ \"use asm\"; M:if(false) {{}(-10); } else  if (undefined) {v1 = this.g2.eval(\"for (var p in b2) { /*ODP-2*/Object.defineProperty(i0, \\\"z\\\", { configurable: false, enumerable: false, get: f0, set: (function() { try { t0.set(a2, ({valueOf: function() { new RegExp(\\\"(?!(?:(?!\\\\uffda*))\\\\\\\\3)\\\", \\\"im\\\");return 19; }})); } catch(e0) { } try { decodeURIComponent } catch(e1) { } t0.set(t1, /(?!\\\\w)?/gy); return g0; }) }); }\"); }\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 36028797018963970.0;\n    var i4 = 0;\n    var i5 = 0;\n    return +((+(-1.0/0.0)));\n    return +((Float64ArrayView[((Int16ArrayView[4096])) >> 3]));\n  }\n  return f; });g0.v2 = true;\ncontinue ;\n/*MXX2*/g1.Date.prototype.setYear = p1;/* no regression tests found */Array.prototype.pop.apply(a0, [o2]);m0.set(g1, (new arguments.callee()));");
/*fuzzSeed-248247344*/count=1358; tryItOut("\"use strict\"; \"use asm\"; t2 = new Int32Array(b0, 34, 5);");
/*fuzzSeed-248247344*/count=1359; tryItOut("testMathyFunction(mathy2, [0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -0x080000000, -1/0, 2**53, 0x080000000, -Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, 2**53+2, Math.PI, 1.7976931348623157e308, -0, -0x0ffffffff, 2**53-2, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 0/0, Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, -(2**53-2), 0x0ffffffff, 0, 1/0, -0x07fffffff, 1, 42, Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=1360; tryItOut("t0 + m1;");
/*fuzzSeed-248247344*/count=1361; tryItOut("a2.push(t0);");
/*fuzzSeed-248247344*/count=1362; tryItOut("/*bLoop*/for (let suhzoi = 0; suhzoi < 2; ++suhzoi) { if (suhzoi % 43 == 26) { a1 = Array.prototype.map.apply(a1, [DataView.prototype.setFloat32.bind(s2)]); } else { t2.valueOf = (function mcc_() { var endvgv = 0; return function() { ++endvgv; f1(/*ICCD*/endvgv % 9 == 1);};})(); }  } ");
/*fuzzSeed-248247344*/count=1363; tryItOut("t2[18];");
/*fuzzSeed-248247344*/count=1364; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1365; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1366; tryItOut("mathy3 = (function(x, y) { return ( ! Math.ceil(( + ( - (Math.min(Math.fround(Math.atan2((x | 0), Math.fround(( - Math.fround(y))))), Math.fround((Math.fround(x) && Math.fround(0/0)))) >>> 0))))); }); ");
/*fuzzSeed-248247344*/count=1367; tryItOut("v0 = t0.length;");
/*fuzzSeed-248247344*/count=1368; tryItOut("o1.v1 = a2.reduce, reduceRight((function(j) { f2(j); }), m2, e0, i2);");
/*fuzzSeed-248247344*/count=1369; tryItOut("mathy5 = (function(x, y) { return Math.sin(Math.abs(((Math.hypot((( - y) >>> 0), ((Math.exp(x) | 0) >>> 0)) >>> 0) ? ( + (0x0ffffffff <= ( ! ( + x)))) : Number.MAX_SAFE_INTEGER))); }); testMathyFunction(mathy5, [-(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, Number.MAX_VALUE, 0/0, Math.PI, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, 0, 0x100000000, 0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, 2**53-2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, 1/0, 0.000000000000001, Number.MIN_VALUE, -0x080000001, 42, -Number.MIN_VALUE, 1, -0, 2**53+2, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=1370; tryItOut("mathy2 = (function(x, y) { return (( + ( + Math.trunc(Math.min(x, Math.fround((Math.imul(Math.atan2(y, -1/0), x) > x)))))) >>> 0); }); testMathyFunction(mathy2, [(new Number(0)), -0, NaN, ({toString:function(){return '0';}}), [0], '/0/', 0, '\\0', ({valueOf:function(){return '0';}}), (function(){return 0;}), (new String('')), [], objectEmulatingUndefined(), /0/, undefined, false, '', 1, true, (new Number(-0)), (new Boolean(false)), (new Boolean(true)), null, ({valueOf:function(){return 0;}}), '0', 0.1]); ");
/*fuzzSeed-248247344*/count=1371; tryItOut("{ void 0; selectforgc(this); } print(/*MARR*/[c, this, c, c, this, c, this, Infinity, this, this, this, Infinity, c, this, Infinity, c, Infinity, Infinity, Infinity, Infinity, c, Infinity, c, this, c, this, Infinity, Infinity, c, Infinity, c, c, this, Infinity, c, this, Infinity, this, c, Infinity, Infinity, c, this, c, this, Infinity, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, c, this, this, Infinity, this, this, c, Infinity, c, c, Infinity, c, this, Infinity, c, Infinity, c, c, Infinity, c, Infinity, this, c, Infinity, c, Infinity, Infinity, Infinity, this, Infinity, this, this, c, c, this, Infinity, this, c, c, this, this].map(this));");
/*fuzzSeed-248247344*/count=1372; tryItOut("\"use strict\"; var rgread = new ArrayBuffer(2); var rgread_0 = new Uint8ClampedArray(rgread); print(rgread_0[0]); g1.v1 = evaluate(\"\\\"use strict\\\"; \\\"use asm\\\"; mathy2 = (function(x, y) { return ( - (Math.min(Math.imul(2**53, ( + (( + (Math.max(2**53, x) >>> 0)) >= ( + -Number.MIN_VALUE)))), ( + Math.max(( ~ y), ( + Math.fround(Math.asin(((y ** 0x0ffffffff) >>> 0))))))) | 0)); }); testMathyFunction(mathy2, [1, '', 0.1, (new String('')), null, (new Number(0)), false, /0/, '0', [], NaN, [0], ({valueOf:function(){return '0';}}), true, '\\\\0', '/0/', (new Number(-0)), 0, ({valueOf:function(){return 0;}}), (function(){return 0;}), undefined, objectEmulatingUndefined(), (new Boolean(false)), ({toString:function(){return '0';}}), -0, (new Boolean(true))]); \", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 13 == 11), noScriptRval: true, sourceIsLazy: window, catchTermination: false }));v2 = b0.byteLength;");
/*fuzzSeed-248247344*/count=1373; tryItOut("h0 = x;");
/*fuzzSeed-248247344*/count=1374; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.cos(((Math.max(y, Math.imul((Math.min((Math.hypot(x, (x >>> 0)) >>> 0), (y >>> 0)) >>> 0), x)) | 0) ** (Math.clz32(y) >>> 0))); }); testMathyFunction(mathy3, ['0', '/0/', (new Number(0)), ({toString:function(){return '0';}}), '\\0', (new Boolean(false)), -0, 0, true, NaN, false, (function(){return 0;}), [0], 1, null, /0/, (new Number(-0)), '', [], (new String('')), (new Boolean(true)), objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), undefined, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-248247344*/count=1375; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + (( + Math.atan2(( + Math.min(Math.fround(Math.pow(Math.fround(x), ((((1/0 >>> 0) != (y >>> 0)) >>> 0) | 0))), x)), Math.fround(( ~ ((((mathy2((y >>> 0), y) >>> 0) >>> 0) & ((((Number.MAX_VALUE | 0) % ( + y)) >>> 0) >>> 0)) >>> 0))))) ? ( + (Math.imul(Math.sin(Math.tan((x >>> 0))), (((Math.round(x) >>> 0) >> (Math.imul(( + (Math.acos((x >>> 0)) >>> 0)), Math.fround(Math.fround(( + Math.atan(x))))) | 0)) | 0)) | 0)) : ( + (mathy3(( - ((Math.fround(Math.log2(Math.fround(x))) >>> y) && 2**53)), ((((x ** Math.fround(mathy3(Math.exp(-0x100000000), Math.fround(y)))) >>> 0) ? (Math.fround(Math.pow(x, Math.fround(x))) >>> 0) : (( - Math.fround((Math.fround(y) <= Math.fround(x)))) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy4, [NaN, 0, 1, (new String('')), false, (function(){return 0;}), (new Number(-0)), true, '0', '/0/', -0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), null, undefined, objectEmulatingUndefined(), [0], (new Boolean(true)), ({toString:function(){return '0';}}), /0/, '', '\\0', (new Boolean(false)), [], (new Number(0)), 0.1]); ");
/*fuzzSeed-248247344*/count=1376; tryItOut("");
/*fuzzSeed-248247344*/count=1377; tryItOut("mathy1 = (function(x, y) { return Math.fround(( + Math.fround(Math.fround(( + ( + (( + Math.atan2(x, y)) ? ( + Math.fround(( ! (( + Math.pow(( + 2**53+2), ( + x))) | 0)))) : ((y & y) >>> 0)))))))); }); testMathyFunction(mathy1, [-0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, 2**53+2, 2**53-2, 0x080000000, Number.MIN_VALUE, 0, 0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, -0x100000000, -1/0, 1/0, 1.7976931348623157e308, -(2**53-2), -0x080000001, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, Math.PI, 2**53, 0x100000000, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, -Number.MIN_VALUE, -(2**53), -0x100000001, 0/0]); ");
/*fuzzSeed-248247344*/count=1378; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.sqrt((( ! (mathy2((x >>> 0), (y >>> 0)) >>> 0)) << Math.asinh(-0x080000000))) && ( + Math.ceil(mathy3(Math.max(((Math.atanh((y | 0)) | 0) >= Math.fround(mathy3(x, Math.fround(( + Math.atan2(y, -Number.MIN_SAFE_INTEGER)))))), ( + ( + Math.asin(x)))), (mathy2((y < Math.fround((Math.fround(x) || (x | 0)))), (y >>> 0)) | 0))))); }); ");
/*fuzzSeed-248247344*/count=1379; tryItOut("a0 = g0.r1.exec(this.s0);");
/*fuzzSeed-248247344*/count=1380; tryItOut("\"use strict\"; { void 0; try { startgc(76218); } catch(e) { } }");
/*fuzzSeed-248247344*/count=1381; tryItOut("testMathyFunction(mathy3, [0x100000000, 2**53+2, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 0x100000001, 2**53-2, 0x080000001, 0x0ffffffff, -0x07fffffff, -(2**53-2), 0x07fffffff, -0x080000000, -0x0ffffffff, Math.PI, -0x100000000, 0/0, -Number.MIN_VALUE, -(2**53), 1/0, -0, Number.MAX_SAFE_INTEGER, 42, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 0.000000000000001, -0x080000001, Number.MIN_VALUE, 0, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=1382; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.pow((mathy2((( ~ y) >>> 0), ( + Math.round(( + ((( + x) >>> 0) <= y))))) | 0), Math.tan(( + (Math.asin(Math.log(Math.atan2((( ~ x) >>> 0), Math.log1p((-(2**53-2) >>> 0))))) >>> 0)))); }); testMathyFunction(mathy4, [0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), 1, 0, -0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 42, -(2**53-2), 2**53-2, -0x100000001, -(2**53+2), 0x100000001, -Number.MIN_VALUE, 2**53+2, 0/0, -0x100000000, 0x080000000, -0x080000001, 0x100000000, Number.MAX_VALUE, 2**53, 0.000000000000001, -1/0, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1383; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.max(((Math.atan2(mathy0((-0x080000001 % x), x), mathy1(Math.fround(((( + Math.sqrt(x)) >> (y | 0)) >>> 0)), y)) >>> 0) != Math.fround(Math.tanh(Math.fround(Math.max(y, Math.fround(( + ( - Math.fround(0.000000000000001))))))))), (Math.ceil((Math.fround(0/0) + x)) <= ( + ( - (x >>> 0))))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -0x080000000, -0x100000000, -1/0, 0x0ffffffff, 1.7976931348623157e308, -0x080000001, -0x100000001, 2**53+2, 0x080000001, 0x100000000, 0x080000000, -(2**53+2), 0/0, 1/0, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, -0x0ffffffff, -Number.MIN_VALUE, 2**53, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, Math.PI, 42, Number.MAX_VALUE, -0, -(2**53-2), -(2**53), -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1384; tryItOut("/*tLoop*/for (let x of /*MARR*/[-(2**53+2), (0/0), this,  'A' ,  'A' , this, (0/0),  'A' ]) { h1.get = f1; }");
/*fuzzSeed-248247344*/count=1385; tryItOut("e2.add(v0);");
/*fuzzSeed-248247344*/count=1386; tryItOut("mathy0 = (function(x, y) { return Math.fround((((((( + (( + y) != Math.fround((( ~ Math.fround(x)) ^ y)))) >>> 0) && (Math.atan(y) >>> 0)) >>> 0) >>> 0) ? (( - (Math.fround(Math.atan2(Math.fround(( ~ ( + (( + Math.fround(( + 0x100000000))) || ( + x))))), Math.fround((( + Math.PI) === ( ! x))))) >>> 0)) >>> 0) : Math.fround(Math.fround(Math.sinh(Math.imul(x, ( ~ ( - y)))))))); }); testMathyFunction(mathy0, [0x07fffffff, -0x100000000, 2**53, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, 1/0, 0x080000001, 0x100000000, -0x0ffffffff, 2**53-2, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, -0x100000001, 1.7976931348623157e308, -0x080000001, -Number.MAX_VALUE, -0, -(2**53), 42, 0x080000000, 0.000000000000001, 0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -1/0, 0/0, Math.PI, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1387; tryItOut("a2 = a2.slice(5, NaN, g1, v2, g2, h2, v1, g2.o1.m2, g0.s1);");
/*fuzzSeed-248247344*/count=1388; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.clz32(((( ~ (Math.tanh((( ~ x) | 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [1/0, -(2**53), -Number.MIN_VALUE, 0x080000001, 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 42, -1/0, -0x080000001, 0x080000000, -0x100000000, 0x100000000, 2**53+2, 0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, 1, Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), 0x100000001, 2**53-2, -0x080000000, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), 0]); ");
/*fuzzSeed-248247344*/count=1389; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x080000001, 42, 1/0, 2**53+2, 0x080000000, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -1/0, -0, 0, -(2**53+2), 2**53-2, -0x100000001, 2**53, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), -0x0ffffffff, Math.PI, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, 0x100000001]); ");
/*fuzzSeed-248247344*/count=1390; tryItOut("\"use asm\"; testMathyFunction(mathy4, [0.1, NaN, (new Boolean(true)), (new String('')), undefined, true, false, ({valueOf:function(){return '0';}}), '/0/', (new Number(0)), ({valueOf:function(){return 0;}}), '\\0', (function(){return 0;}), [], [0], -0, '', 1, 0, (new Number(-0)), (new Boolean(false)), objectEmulatingUndefined(), null, '0', /0/, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-248247344*/count=1391; tryItOut("/*MXX2*/g2.Object.seal = h0;");
/*fuzzSeed-248247344*/count=1392; tryItOut("mathy1 = (function(x, y) { return ( + Math.atan(( + (Math.imul(( ~ (Math.fround(( - (x >>> 0))) | (((Math.imul((1.7976931348623157e308 | 0), (x | 0)) | 0) >>> 0) , y))), ( + (Math.imul(((( ~ -(2**53)) | 0) | 0), (( + (Math.max(-1/0, x) | 0)) | 0)) | 0))) | 0)))); }); testMathyFunction(mathy1, [2**53, 0x0ffffffff, -(2**53-2), -1/0, -0x100000001, -(2**53), Number.MIN_VALUE, 0x100000000, 1/0, 0x080000000, -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, -Number.MAX_VALUE, 2**53+2, 0, 0/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x080000001, 0.000000000000001, Math.PI, 1, -(2**53+2), -0x080000001, -0, 42]); ");
/*fuzzSeed-248247344*/count=1393; tryItOut("\"use strict\"; for (var v of f1) { try { v0 = t0.BYTES_PER_ELEMENT; } catch(e0) { } try { f0 + ''; } catch(e1) { } try { g0.v1 = a0.some(h2, h0, s2, o0, b0); } catch(e2) { } Array.prototype.forEach.call(a2, (function() { try { b0.toString = (function() { t0 + ''; return g2; }); } catch(e0) { } try { g1.g0.g2.v2 = r2.exec; } catch(e1) { } try { s2 += 'x'; } catch(e2) { } selectforgc(o0); return p1; })); }");
/*fuzzSeed-248247344*/count=1394; tryItOut("this.g0.s0 += s1;");
/*fuzzSeed-248247344*/count=1395; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float32ArrayView[0]) = ((+((d1))));\n    d0 = (d0);\n    d1 = (+(0.0/0.0));\n    d0 = (((+(1.0/0.0))) * (((0x5bf51c1e) ? (+atan2(((d0)), ((+(~~(d1)))))) : (d0))));\n    d0 = (d1);\n    {\n      d1 = (d1);\n    }\n    return ((((0xfff112c0) ? (/*FFI*/ff(((((((d0)) * ((+(0.0/0.0))))) % ((((d1)))))), (((((0x642caf19) != (0x7fffffff))+(0x18d31357)) << ((0xfe02712a)))), ((d1)), ((~~(d0))), ((((0x14e65031)) | ((0x3b11dba9)))))|0) : (0xfa43366a))*-0xfffff))|0;\n  }\n  return f; })(this, {ff: String.prototype.repeat}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=1396; tryItOut("mathy3 = (function(x, y) { return ( + (( + Math.exp(( - Math.hypot((x !== x), (( + (0x100000000 & x)) ? ( + x) : ( + x)))))) & Math.max((( ! (mathy2(x, y) >>> 0)) >>> 0), ( ! Math.imul(Math.min(mathy0((-0x100000001 | 0), x), x), ((Math.acosh((x | 0)) | 0) == y)))))); }); testMathyFunction(mathy3, /*MARR*/[ '\\0' , true,  '\\0' , objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true,  '\\0' , true, true,  '\\0' ,  '\\0' , true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), true,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), true, true,  '\\0' , objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true,  '\\0' , objectEmulatingUndefined(), true, true,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), true, true,  '\\0' , true, objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' ,  '\\0' , objectEmulatingUndefined(),  '\\0' , true, objectEmulatingUndefined(),  '\\0' , true, true, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), true, true, objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , true, true, objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  '\\0' , true,  '\\0' , objectEmulatingUndefined(), true, true, true, true, true, objectEmulatingUndefined(), true,  '\\0' ,  '\\0' , true,  '\\0' , objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, objectEmulatingUndefined(),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , true,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , objectEmulatingUndefined(), true,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' , true, true, objectEmulatingUndefined(),  '\\0' , true, objectEmulatingUndefined(),  '\\0' ,  '\\0' , objectEmulatingUndefined(), true, objectEmulatingUndefined(),  '\\0' , true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,  '\\0' ,  '\\0' , objectEmulatingUndefined(), true, true,  '\\0' , true]); ");
/*fuzzSeed-248247344*/count=1397; tryItOut("\"use asm\"; h0.toSource = (function mcc_() { var wnpdhk = 0; return function() { ++wnpdhk; if (/*ICCD*/wnpdhk % 9 == 5) { dumpln('hit!'); try { i2.send(m1); } catch(e0) { } g1 = x; } else { dumpln('miss!'); try { t0 = new Int32Array(b2, 96, ({valueOf: function() { e0.has(b2);return 0; }})); } catch(e0) { } try { v0 = Array.prototype.every.apply(a0, [(function(j) { if (j) { try { for (var p in f2) { try { g1.i0 = e1.values; } catch(e0) { } a0.forEach((function(j) { if (j) { try { g1.a2 = o1.g0.objectEmulatingUndefined(); } catch(e0) { } a2.shift(); } else { try { v1 = t2.length; } catch(e0) { } try { o2.a2.splice(NaN, null); } catch(e1) { } try { Object.seal(g1); } catch(e2) { } a1 = a0.concat(g0.a1, t0); } })); } } catch(e0) { } try { v2 = b2.byteLength; } catch(e1) { } try { print(uneval(s0)); } catch(e2) { } b1 + t0; } else { try { m0.has(11 ? \"\\uA8ED\" :  /x/ .valueOf(\"number\")); } catch(e0) { } try { v2 = this.t0.length; } catch(e1) { } try { g1.o1.o1.b0 + ''; } catch(e2) { } p2 = a2[10]; } }), g0]); } catch(e1) { } p2 + ''; } };})();");
/*fuzzSeed-248247344*/count=1398; tryItOut("\"use strict\"; v1 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-248247344*/count=1399; tryItOut("mathy5 = (function(x, y) { return ( + Math.clz32(( + ((Math.atan2(x, ((Math.tan((((y | y) && ( + (( + y) ? ( + x) : ( + mathy0(x, y))))) >>> 0)) >>> 0) >>> 0)) >>> 0) ? (( ~ Math.fround(Math.acos(Math.fround(x)))) || mathy1(Math.log1p(( + y)), Math.fround(y))) : Math.max(( - Math.min(-0x080000000, x)), x))))); }); testMathyFunction(mathy5, [-0x100000001, -Number.MAX_VALUE, 0x080000000, 1, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 2**53+2, 2**53, 0x080000001, -0x080000001, Number.MIN_VALUE, 0x100000000, -0x080000000, -0x07fffffff, -1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, 0.000000000000001, -(2**53+2), 0x07fffffff, -Number.MIN_VALUE, 42, Number.MAX_VALUE, 1/0, 0, 2**53-2, -0x100000000]); ");
/*fuzzSeed-248247344*/count=1400; tryItOut("\"use strict\"; m2.has(e0);");
/*fuzzSeed-248247344*/count=1401; tryItOut("for (var p in f0) { try { v1 = g2.eval(\"function g0.f1(this.i0)  { \\\"use strict\\\"; for (var v of p1) { try { Array.prototype.shift.apply(a1, [\\\"\\\\uE915\\\"]); } catch(e0) { } try { v1 = g1.eval(\\\"this.i0\\\"); } catch(e1) { } try { f0.__proto__ = o0; } catch(e2) { } i2 = new Iterator(g0.m0); }\\nprint(x);\\n } \"); } catch(e0) { } try { m0.has(o0.b0); } catch(e1) { } v0 = a2.length; }");
/*fuzzSeed-248247344*/count=1402; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=1403; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ ((( + (Math.fround(Math.log2(( ~ ((x !== x) >>> 0)))) >>> 0)) >>> 0) ? (Math.hypot((Math.sign((y | 0)) | 0), ( - (Math.imul(Math.fround(x), Math.fround(x)) >>> 0))) | 0) : Math.acos(y))) >>> 0); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, Math.PI, Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, -1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 0x100000000, -0x0ffffffff, Number.MAX_VALUE, -(2**53-2), 1/0, 42, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, -0x100000000, 0, 0x080000000, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, 1, 2**53, -(2**53), -0x100000001, 0.000000000000001, -0x080000000, 0/0, 0x0ffffffff, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1404; tryItOut("t2 = new Uint16Array(t0);");
/*fuzzSeed-248247344*/count=1405; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max(((((Math.fround((mathy0(y, 0) !== Math.fround(y))) >>> 0) >>> 0) * ((( ! y) >>> 0) >>> 0)) >>> 0), Math.max(Math.fround(Math.cbrt(( - x))), ((Math.fround(mathy1(Math.fround(x), ( + (( + ((x + (y >>> 0)) >>> 0)) && ( + Math.exp(Math.fround(y))))))) ** (( + mathy1(( + Number.MAX_VALUE), ( + (Math.min(y, (-1/0 >>> 0)) >>> 0)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-0x100000000, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 2**53-2, 0x080000000, Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, 0, 0/0, 1, -0x100000001, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, -(2**53), Math.PI, Number.MIN_VALUE, 2**53+2, 0x100000001, -Number.MAX_VALUE, 0x07fffffff, 1/0, 0.000000000000001, -0x0ffffffff, -1/0, 0x0ffffffff, 1.7976931348623157e308, 0x080000001, 42]); ");
/*fuzzSeed-248247344*/count=1406; tryItOut("testMathyFunction(mathy1, [Math.PI, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 42, 1/0, -0x0ffffffff, 1.7976931348623157e308, 0, 0x080000001, 0x0ffffffff, 2**53-2, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, 0x100000000, -0x100000001, -0x100000000, 2**53+2, 1, Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, 0x100000001, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, -0, Number.MAX_VALUE, -1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1407; tryItOut("mathy4 = (function(x, y) { return (Math.acos((( + mathy2(( + Math.max(Math.hypot(mathy3(x, 0x07fffffff), mathy0((( + y) ? ( + -0x0ffffffff) : ( + mathy2(x, x))), x)), (Math.sin((( + (y | 0)) | 0)) | 0))), Math.sinh(x))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [1, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 42, -0x080000001, 0x100000001, -0, -0x100000001, -Number.MIN_VALUE, -(2**53), 0x0ffffffff, 0.000000000000001, 0x080000001, -1/0, 0x100000000, -0x100000000, -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, -(2**53+2), 0, 0/0, 1/0, -Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1408; tryItOut("s1.toSource = objectEmulatingUndefined;");
/*fuzzSeed-248247344*/count=1409; tryItOut("/*\n*/b0 + this.v1;function x(c) { yield {x: []} = c } print(x);{}");
/*fuzzSeed-248247344*/count=1410; tryItOut("{ void 0; try { (enableSingleStepProfiling()) } catch(e) { } }");
/*fuzzSeed-248247344*/count=1411; tryItOut("g1.h0.iterate = JSON.parse.bind(o2.b2);");
/*fuzzSeed-248247344*/count=1412; tryItOut("h0.set = (function(j) { if (j) { try { o2.o1.valueOf = (function() { try { e1 = new Set(t1); } catch(e0) { } for (var v of b0) { try { Object.prototype.unwatch.call(g1.p1,  /x/ ); } catch(e0) { } try { h2.defineProperty = f0; } catch(e1) { } t0[15] = i0; } return t1; }); } catch(e0) { } try { o0.b0 = new SharedArrayBuffer(10); } catch(e1) { } try { function f0(i1)  { \"use strict\"; this.v0 = (p2 instanceof g2); }  } catch(e2) { } print(uneval(e1)); } else { try { v1 = Object.prototype.isPrototypeOf.call(v2, o1); } catch(e0) { } try { i2.send(g2); } catch(e1) { } try { v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (void (4277)), noScriptRval: true, sourceIsLazy: true, catchTermination: (x(x)) })); } catch(e2) { } m2.has(p2); } });");
/*fuzzSeed-248247344*/count=1413; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max(( + Math.pow(( + Math.fround(Math.log2((( + (( + -0) > -(2**53-2))) && x)))), ((( + y) * x) << Math.round(((x != Math.pow(x, Math.fround((Math.hypot((x >>> 0), (x >>> 0)) >>> 0)))) >>> 0))))), ( + Math.max((x / x), ( + y)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0, 0x080000000, 1, 1/0, -Number.MAX_VALUE, -0x100000001, 2**53, -1/0, -0x07fffffff, 0x100000000, 1.7976931348623157e308, 2**53+2, -Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 0/0, -(2**53), 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, 0x0ffffffff, 0x080000001, 42, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, Math.PI, -0x100000000, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=1414; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ Math.abs(((((y >> y) | 0) + (Math.acosh((y >= ((( - 1) == 2**53-2) >>> 0))) | 0)) | 0))) | 0); }); testMathyFunction(mathy0, [1/0, 0x080000000, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 0, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, 1, -0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -0x100000000, Math.PI, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, 42, 0/0, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -0x100000001, 0x100000000, -0, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1415; tryItOut("g1.s0 += 'x';");
/*fuzzSeed-248247344*/count=1416; tryItOut("this.m1.set(b2, p0);");
/*fuzzSeed-248247344*/count=1417; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.log((mathy1(Math.fround(Math.max(y, Math.fround(Math.min(Math.fround(mathy1(Math.fround(Math.atan2(( + Number.MAX_VALUE), ( + Number.MAX_VALUE))), Math.sign(x))), x)))), Math.log10(( + Math.asin(( + (( ~ x) | 0)))))) | 0)); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), undefined, '', NaN, '/0/', (new Number(0)), (new Boolean(false)), null, '0', (new Boolean(true)), ({toString:function(){return '0';}}), /0/, (new Number(-0)), 1, [], false, [0], ({valueOf:function(){return 0;}}), (function(){return 0;}), 0.1, -0, ({valueOf:function(){return '0';}}), '\\0', 0, true, (new String(''))]); ");
/*fuzzSeed-248247344*/count=1418; tryItOut("s2 += 'x';function 15(this.x, \u3056, ...y) { \"use strict\"; /*RXUB*/var r =  /x/g ; var s = \"\"; print(s.replace(r, 'x'));  } ;");
/*fuzzSeed-248247344*/count=1419; tryItOut("/*MXX1*/var this.o1 = o2.o0.g1.String.name;");
/*fuzzSeed-248247344*/count=1420; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 590295810358705700000.0;\n    return +((1.2089258196146292e+24));\n    i1 = (0xdf6385b5);\n    {\n      d0 = (((d0)) / ((d2)));\n    }\n    d0 = (d0);\n    {\n      i1 = ((0x22c272f7));\n    }\n    {\n      {\n        (Int8ArrayView[((0xa714fd04) / (0xffffffff)) >> 0]) = ((i1));\n      }\n    }\n    return +((NaN));\n  }\n  return f; })(this, {ff: mathy2}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, -Number.MIN_VALUE, 2**53, -(2**53-2), 2**53-2, -0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0x07fffffff, 0x080000001, 1/0, 0.000000000000001, 0, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, -Number.MAX_VALUE, -0, -0x080000001, -0x0ffffffff, 0x080000000, 1, 2**53+2, 1.7976931348623157e308, 0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 42, -(2**53+2)]); ");
/*fuzzSeed-248247344*/count=1421; tryItOut("mathy5 = (function(x, y) { return mathy3((Math.fround(Math.hypot(Math.fround((Math.fround((( ! x) >>> 0)) && Math.exp((-0 >>> 0)))), ( ~ ( + Math.max(0x080000001, (Math.fround(( - Math.fround(Math.fround(Math.min(x, Math.fround(y)))))) >>> 0)))))) >>> 0), (Math.sin(( + ( - (Math.pow((Math.expm1(y) >>> 0), (x >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -0x07fffffff, -0x080000000, 0, 0x080000000, -(2**53+2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 2**53, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 0x100000000, 0.000000000000001, 0x080000001, 42, 1/0, 2**53-2, -0x100000001, 0/0, -0, 0x0ffffffff, Number.MIN_VALUE, 0x100000001, 1, 2**53+2, -0x100000000, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-248247344*/count=1422; tryItOut("e1 = a2[1];(void schedulegc(g2));");
/*fuzzSeed-248247344*/count=1423; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(( ~ Math.fround(Math.hypot(y, ((( + (( + ( + mathy0(( + y), y))) || ( + mathy0(( + y), ( + y))))) * x) && Math.hypot(y, x)))))), Math.fround(( + Math.fround(Math.trunc(( + Math.pow(( + 42), ( + -0x100000000)))))))); }); testMathyFunction(mathy1, ['', NaN, (new Boolean(true)), null, ({toString:function(){return '0';}}), [0], ({valueOf:function(){return '0';}}), '\\0', '0', (new String('')), 0.1, 1, (new Number(0)), 0, (new Boolean(false)), (function(){return 0;}), '/0/', objectEmulatingUndefined(), false, undefined, [], (new Number(-0)), -0, true, ({valueOf:function(){return 0;}}), /0/]); ");
/*fuzzSeed-248247344*/count=1424; tryItOut("if((x % 6 != 1)) e2.has(a1); else /* no regression tests found */");
/*fuzzSeed-248247344*/count=1425; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Boolean(false)), 1, '', (new Boolean(true)), ({valueOf:function(){return 0;}}), -0, '0', ({toString:function(){return '0';}}), /0/, true, [], '/0/', false, 0, (function(){return 0;}), (new String('')), objectEmulatingUndefined(), NaN, '\\0', ({valueOf:function(){return '0';}}), (new Number(0)), [0], 0.1, undefined, null, (new Number(-0))]); ");
/*fuzzSeed-248247344*/count=1426; tryItOut("\"use asm\"; /*vLoop*/for (nmmfsl = 0; nmmfsl < 103 && (( '' )((6.__defineSetter__(\"e\", new RegExp(\"(?=[^\\\\u1B0E\\\\w\\u00e7-\\\\b\\\\W]|\\\\cQ\\\\W+|\\\\1+?(?!\\\\B))*^(?:[^])(?!(?:[^])[^]){1,4}\", \"im\"))), new RegExp(\"[^\\\\0-\\u6853]|(\\\\D|[^]{3,6})?(?!\\\\3|[^]){4,}\", \"gi\"))() ? \u000c/*UUV2*/(e.trimRight = e.setHours) : String.prototype.small(/(?!.?)/gym, ((arguments.callee)(null, \"\\u9B49\")))); ++nmmfsl) { var b = nmmfsl; /*vLoop*/for (vmqqwq = 0; vmqqwq < 50; ++vmqqwq) { const y = vmqqwq; (Math); }  } ");
/*fuzzSeed-248247344*/count=1427; tryItOut("\"use strict\"; print((\n(x = ({})) || x));\nprint(o2);\n");
/*fuzzSeed-248247344*/count=1428; tryItOut("\"use strict\"; let(eval, x = (yield (-29.d) =  /* Comment */[z1])) ((function(){with({}) this.zzz.zzz;})());");
/*fuzzSeed-248247344*/count=1429; tryItOut("m0.has(m0);");
/*fuzzSeed-248247344*/count=1430; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.log1p((( ! (y | 0)) >>> ( ~ x))), ( ! ((y % y) | 0))); }); testMathyFunction(mathy1, [[0], '/0/', [], null, /0/, (new String('')), (new Number(0)), '0', 0.1, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Boolean(true)), (function(){return 0;}), (new Boolean(false)), '\\0', '', 0, objectEmulatingUndefined(), NaN, 1, (new Number(-0)), undefined, true, false, -0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-248247344*/count=1431; tryItOut("a2.unshift(g0, e2, t1, h1);");
/*fuzzSeed-248247344*/count=1432; tryItOut("testMathyFunction(mathy0, [-0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 42, 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, 1/0, 2**53, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, Number.MIN_VALUE, -0x080000000, 0x100000000, 0x080000001, 0.000000000000001, -0x0ffffffff, 2**53+2, 1, 0x0ffffffff, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, -(2**53), -(2**53-2), 2**53-2, -Number.MAX_VALUE, 0, 0x080000000, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1433; tryItOut("\"use strict\"; m0.set(m0, b1);");
/*fuzzSeed-248247344*/count=1434; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.sinh((mathy0((mathy1((mathy0(( + x), (y | 0)) | 0), (y | 0)) | 0), ( - ( ! (x & (Math.min(y, x) >>> 0))))) ? Math.fround((x >= (( ! (y >>> 0)) >>> 0))) : Math.acos(( ! y)))); }); testMathyFunction(mathy2, [0.000000000000001, Number.MAX_VALUE, -(2**53+2), 0x080000000, 2**53, -0x080000001, 0x080000001, -0x100000001, -0, 1/0, -(2**53-2), Number.MIN_VALUE, 1, 42, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0x0ffffffff, 0/0, 0x0ffffffff, Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, -0x07fffffff, 0, 2**53-2, -1/0]); ");
/*fuzzSeed-248247344*/count=1435; tryItOut("testMathyFunction(mathy5, /*MARR*/[({}), true, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, ({}), true, true, [(void 0)]]); ");
/*fuzzSeed-248247344*/count=1436; tryItOut("v2 = r2.unicode;");
/*fuzzSeed-248247344*/count=1437; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch ((((0xfaffb158)-(0xfddaed86)+(0x53d6069b)) ^ ((0x870e776)-(0xf8a9c378)-(0xd134db12)))) {\n      case -3:\n        (Int8ArrayView[4096]) = (((d1) < (-513.0)));\n        break;\n      case -3:\n        return (((((i0))|0)))|0;\n      case -3:\n        return (((((((0xd50ab3cd)+(0xffffffff))>>>(((Uint32ArrayView[1])))) > (((0xfa0c4d7b)-(0xfe06be28))>>>(((0x536b7820))))) ? ((((-0x5beee36) % (-0x8000000))>>>((0x59d696db)+(0xffffffff)+(0x8c338e0d)))) : (i0))+(0x33d9a6dd)-(0xeaf37f9e)))|0;\n      case -2:\n        i0 = (i0);\n        break;\n      case -1:\n        {\n          i0 = (0xfbf13f5d);\n        }\n        break;\n      case 0:\n        return (((0xe519e03a)-((-2.3611832414348226e+21) <= (d1))-(((((abs((abs((0x7b42abf7))|0))|0))-((((0x111f62c4))>>>((-0x8000000))))) >> ((0xffffffff)-(i0))) >= ((0xfffff*((((0xffffffff)) & ((0xfb4569dc))))) << ((-0x8000000)-(0x7c158407))))))|0;\n        break;\n      case -1:\n        d1 = (d1);\n    }\n    switch ((0x382d46f6)) {\n    }\n    (Float32ArrayView[1]) = ((+(0.0/0.0)));\n    i0 = (i0);\n    i0 = (0xfef570e0);\n    return (((~~(+((((((0xa4a1e37e))>>>((0xffffffff))) <= (((0xffffffff))>>>((0xaa21f9f2)))))>>>((Int8ArrayView[((i0)-(i0)) >> 0]))))) / (imul(((0xeefd4a5)), (0xb39ad8ee))|0)))|0;\n  }\n  return f; })(this, {ff: mathy1}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), 0x080000000, 0, 0/0, -0x07fffffff, -0x0ffffffff, -0x080000001, 0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, -Number.MAX_VALUE, 42, 0x100000000, -0x080000000, 1.7976931348623157e308, -1/0, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, -0, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 2**53, -0x100000000, Number.MIN_VALUE, 0x07fffffff, -(2**53+2), 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-248247344*/count=1438; tryItOut("\"use strict\"; i1.__iterator__ = (function() { for (var j=0;j<65;++j) { f0(j%5==1); } });");
/*fuzzSeed-248247344*/count=1439; tryItOut("v0 = evalcx(\"Object.prototype.watch.call(b0, \\\"__parent__\\\", (function mcc_() { var vpilcq = 0; return function() { ++vpilcq; if (/*ICCD*/vpilcq % 7 == 4) { dumpln('hit!'); try { v2 = (e2 instanceof this.p1); } catch(e0) { } try { o0.v2 = a0.length; } catch(e1) { } e2.add(v0); } else { dumpln('miss!'); try { o2.e0.__iterator__ = f2; } catch(e0) { } try { v1 = x; } catch(e1) { } a0 = arguments.callee.caller.caller.arguments; } };})());\", this.o2.g1);");
/*fuzzSeed-248247344*/count=1440; tryItOut("\"use strict\"; var r0 = x + 2; var r1 = r0 + x; var r2 = 2 * 5; var r3 = r0 & 9; var r4 = 9 + x; r2 = 3 ^ r4; var r5 = 4 * x; var r6 = 1 + r0; var r7 = 7 + r6; var r8 = 9 + r2; var r9 = 7 - 9; var r10 = 5 | r4; r5 = 2 / r3; var r11 = r5 / r7; r10 = r10 ^ 0; var r12 = r3 - r9; var r13 = x % r11; var r14 = 2 ^ 9; var r15 = r2 - r6; var r16 = r15 | r1; r0 = r16 | r0; var r17 = r1 - r10; var r18 = 4 * 9; var r19 = r0 | r5; var r20 = 0 % r13; var r21 = r13 ^ r17; var r22 = r4 | r9; var r23 = r11 & r18; var r24 = 7 | r16; var r25 = 6 & r20; var r26 = r18 + r24; var r27 = 3 - r23; var r28 = 8 * r12; var r29 = 0 + r13; var r30 = r0 + r23; var r31 = r7 / 6; var r32 = 1 % r4; var r33 = r21 * r31; var r34 = r0 + r31; var r35 = r12 * r26; r3 = 1 ^ r4; var r36 = 7 + r7; r23 = r2 / r3; var r37 = r8 ^ r22; var r38 = r32 | r11; var r39 = 8 & r8; var r40 = r18 - r32; var r41 = r4 % r20; print(r13); r38 = r41 + r17; var r42 = r7 ^ r19; r35 = r15 + r30; var r43 = r37 + r21; r32 = 9 | r10; r26 = r12 | r38; r31 = r0 * r22; r29 = r4 / 3; r17 = r27 / r0; r8 = r22 * r40; var r44 = r14 | r28; r7 = r28 * r7; var r45 = r3 ^ r33; var r46 = r13 + 1; r4 = r7 + 7; var r47 = 4 % 2; var r48 = r31 ^ r4; var r49 = 2 | 3; var r50 = r8 + r42; var r51 = 0 ^ r39; var r52 = r43 % 8; var r53 = r47 / r16; var r54 = r32 | r19; var r55 = r48 + r33; var r56 = 2 * r24; var r57 = r25 / r18; var r58 = r26 | 4; x = r32 + r32; var r59 = r16 | r15; r59 = r5 / r39; var r60 = r22 % 5; r46 = 5 / r10; r16 = 4 - r34; var r61 = 8 - r10; var r62 = 3 % r7; var r63 = 7 + r47; r61 = 3 % r9; var r64 = x / r7; var r65 = 8 ^ r4; var r66 = r31 * r36; var r67 = r10 ^ r24; r8 = r2 ^ r67; var r68 = 5 - r3; var r69 = x % r33; print(r32); r57 = r9 * r44; var r70 = 9 | r47; r55 = r38 ^ r38; var r71 = r55 & r40; var r72 = r8 * 4; var r73 = 7 + r22; r23 = 8 + r24; r27 = r24 - r40; var r74 = r68 % r5; var r75 = r4 / r60; r12 = r9 ^ 4; var r76 = 8 + r38; print(r74); print(r12); var r77 = 2 | r57; var r78 = r40 ^ r63; var r79 = 6 * r40; var r80 = 5 & r38; var r81 = r18 ^ r11; var r82 = 9 + r67; var r83 = r41 % r43; var r84 = 0 / r58; r7 = r54 ^ r60; r39 = 6 ^ r6; var r85 = r73 % 9; var r86 = r8 & 0; var r87 = 5 | r14; var r88 = r79 + 3; var r89 = 1 | r15; var r90 = 4 / 3; var r91 = r58 ^ 2; print(r25); r47 = r37 * r45; var r92 = r35 + 8; var r93 = r11 ^ 0; var r94 = r10 - 8; var r95 = r6 % r40; var r96 = r19 * r78; var r97 = r69 & 9; r8 = r19 / r36; var r98 = r29 * 7; var r99 = r29 % 9; var r100 = r52 & 3; var r101 = r48 & r76; var r102 = r50 | 2; var r103 = r100 % r83; r69 = r76 & r34; r52 = r81 & r38; var r104 = r3 % r51; var r105 = r97 | r81; var r106 = r67 + r67; var r107 = 3 * 1; var r108 = r19 * r6; r32 = r67 - r72; var r109 = r97 - r32; var r110 = 2 / 5; var r111 = r73 / r44; var r112 = r95 - r83; var r113 = r26 & 9; var r114 = r2 + 6; var r115 = r111 | 2; var r116 = 1 % r90; var r117 = 7 | r84; var r118 = 1 - 7; var r119 = r46 + r13; r119 = r92 / r28; var r120 = r8 | r50; var r121 = r97 + r71; var r122 = 5 - r116; var r123 = r80 & r119; var r124 = 0 | r105; r55 = r17 / r89; var r125 = r24 * 4; var r126 = r104 ^ r89; var r127 = r42 - 5; var r128 = r42 % r79; var r129 = r6 ^ r109; var r130 = r102 | 3; var r131 = r28 | r32; r40 = r71 ^ r30; var r132 = 5 + r56; var r133 = r20 + r132; var r134 = r8 * r45; r11 = 7 + r7; var r135 = r131 ^ r49; r86 = r77 - r133; var r136 = 9 - r28; var r137 = r118 * r4; r122 = r110 + 5; var r138 = 2 % 5; var r139 = 5 + r57; r51 = r71 / 9; var r140 = 9 * r119; var r141 = r78 % r38; r9 = 7 + 7; r22 = r114 - r134; var r142 = r126 * r127; var r143 = r5 & 8; r42 = r29 + r15; var r144 = 4 & 0; var r145 = r110 | r7; var r146 = r103 * r33; print(r117); var r147 = r66 % r142; var r148 = 4 + r37; var r149 = r49 | r17; var r150 = r52 * r79; print(r112); var r151 = r63 * r126; print(r120); var r152 = r122 - r23; r22 = r84 / r68; var r153 = r22 & r35; r29 = 2 - 2; var r154 = r28 % 7; var r155 = 4 ^ r9; var r156 = r124 | r10; var r157 = r20 | 8; var r158 = 2 - r116; var r159 = 6 / r28; var r160 = r32 % r142; print(r71); var r161 = r151 | r26; print(r127); var r162 = r120 ^ r17; var r163 = 1 / r69; r77 = r131 ^ r24; var r164 = r112 & r92; var r165 = 5 + r35; var r166 = r75 ^ r82; var r167 = r124 & 9; var r168 = 6 + 7; r4 = r149 * r67; var r169 = r167 - 1; r92 = r4 ^ 1; var r170 = r32 | 8; var r171 = r80 / 4; var r172 = r64 & r43; var r173 = 0 | r78; r27 = r166 * r138; var r174 = r107 & 3; r3 = r69 * r9; r164 = r10 | r109; var r175 = r13 | r65; var r176 = r66 - r141; var r177 = 1 & r24; var r178 = r37 | r144; var r179 = 8 % 2; var r180 = r93 + 0; var r181 = r82 / 8; r88 = r4 / r20; var r182 = r99 | r85; var r183 = 1 ^ r76; r18 = r177 % 5; var r184 = 9 + 8; var r185 = r22 & r66; r32 = r76 ^ r103; var r186 = r65 + r149; \n/*RXUB*/var r = /(?!\\B\\2)|.+?|(?:(?!.))+?|(?!(?:(?:[^]|(?=.))))*?|(?!(?!\\\u00b8\\B(?!.))(?:[\u00aa\\WD-\u4ca1])[^]+*?){2,}(?:(?:[^]?))/gy; var s = \"\"; print(s.search(r)); print(r.lastIndex); \n");
/*fuzzSeed-248247344*/count=1441; tryItOut("\"use strict\"; { void 0; void schedulegc(this); } x;");
/*fuzzSeed-248247344*/count=1442; tryItOut("v2 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-248247344*/count=1443; tryItOut("/*RXUB*/var r = r0; var s = \"\\u0008\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1444; tryItOut("\"use strict\"; a1.unshift(s2, g1.s1, g1.t0, b2, f1);");
/*fuzzSeed-248247344*/count=1445; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.max((Math.abs(( ! Math.fround(Math.hypot(Math.fround((Math.fround(x) >> Math.fround(y))), ( ~ Math.exp(x)))))) >>> 0), (( ~ ( + ( + y))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x100000000, 0/0, 1.7976931348623157e308, -0x080000000, -(2**53-2), 0x100000000, -0, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 2**53, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 1, 0x080000001, 2**53+2, Number.MIN_VALUE, 1/0, 0x0ffffffff, -0x0ffffffff, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0, 42, 0x080000000, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1446; tryItOut("(/(?!(?!\\u0000|(?!^)+?+??))/ym);");
/*fuzzSeed-248247344*/count=1447; tryItOut("\"use strict\"; \"use asm\"; this.a2 = Array.prototype.filter.apply(a2, [(function() { try { this.p1.toSource = this.f0; } catch(e0) { } try { g2.v1 = evaluate(\"function f0(a1) \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    {\\n      i2 = ((0x978cb78e) ? (i1) : (0xdb63b17d));\\n    }\\n    i2 = (1);\\n    return ((((0x59c70abf))-(0xec6a9fd1)-(1)))|0;\\n  }\\n  return f;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: Math.log1p.prototype, noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 4 == 0) })); } catch(e1) { } try { Math.atan2(12, NaN = w = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: Array.prototype.keys, getOwnPropertyNames: undefined, delete: function() { throw 3; }, fix: function() { throw 3; }, has: function(name) { return name in x; }, hasOwn: decodeURI, get: function(receiver, name) { return x[name]; }, set: this, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })( '' ), (\u3056 = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function (z)this, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: DataView.prototype.getFloat32, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(new RegExp(\"(?:\\\\1)|(?:.\\\\b)|(?=$){2}.*|[^]*\", \"gy\")), let (z) \"\\u45AA\")))) = a0[0]; } catch(e2) { } m1.delete(p1); return s0; })]);");
/*fuzzSeed-248247344*/count=1448; tryItOut("var plsaos = new ArrayBuffer(0); var plsaos_0 = new Float64Array(plsaos); print(plsaos_0[0]); plsaos_0[0] = -3; let (plsaos_0[0]) { ( /x/g ); }e0 + a1;g0 + '';print(plsaos_0);a2 = new (eval)(this) for each (plsaos_0[2] in this) if (new RegExp(\"((?=(?:.|\\\\B{0,}))+?)\", \"gim\"));print(\"\\u4952\");/*MXX3*/g0.Element = this.g2.Element;/*RXUB*/var r = new RegExp(\"(?!(\\\\1)\\\\w)(?=(?:\\\\cA)?.*?)*?\", \"y\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); var kdufmu = new SharedArrayBuffer(16); var kdufmu_0 = new Uint16Array(kdufmu); print(kdufmu_0[0]); i1 = new Iterator(m0, true);this;/*wrap2*/(function(){ var gszedv =  /x/ ; var dmpnno = Uint32Array; return dmpnno;})()");
/*fuzzSeed-248247344*/count=1449; tryItOut("/*RXUB*/var r = /(?=\\S*|.|(?!\\t)|\\3+??)/gy; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1450; tryItOut("/*infloop*/L:for(let c = \n\"\\u7F21\"; (eval(\"( '' );\")); x.throw(\"\\u1907\")) g1 + '';");
/*fuzzSeed-248247344*/count=1451; tryItOut("{ void 0; try { gcparam('sliceTimeBudget', 90); } catch(e) { } } (0x5a827999)\n");
/*fuzzSeed-248247344*/count=1452; tryItOut("mathy4 = (function(x, y) { return ( - Math.fround(Math.min(Math.fround(Math.acos(x)), Math.fround(( + ( ~ ( + Math.abs(x)))))))); }); testMathyFunction(mathy4, /*MARR*/[5.0000000000000000000000, new Boolean(true), new Boolean(true),  /x/ ,  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ , 5.0000000000000000000000, 5.0000000000000000000000,  /x/ ,  /x/ , 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), 5.0000000000000000000000,  /x/ ]); ");
/*fuzzSeed-248247344*/count=1453; tryItOut("\"use strict\"; m0.delete(v0);");
/*fuzzSeed-248247344*/count=1454; tryItOut("/*bLoop*/for (var rfnqki = 0, x; rfnqki < 11 && (/*RXUE*/new RegExp(\"(?=\\\\S)\", \"gi\").exec(\"\\ufe8b\")); ++rfnqki) { if (rfnqki % 4 == 1) { a2 + ''; } else { h1 = ({getOwnPropertyDescriptor: function(name) { e2 = new Set;; var desc = Object.getOwnPropertyDescriptor(a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v1 = (this.e1 instanceof i0);; var desc = Object.getPropertyDescriptor(a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { o2.s0 = '';; Object.defineProperty(a0, name, desc); }, getOwnPropertyNames: function() { selectforgc(o0);; return Object.getOwnPropertyNames(a0); }, delete: function(name) { e0 + g0;; return delete a0[name]; }, fix: function() { o1.a0 = arguments.callee.arguments;; if (Object.isFrozen(a0)) { return Object.getOwnProperties(a0); } }, has: function(name) { v1 = evaluate(\"/* no regression tests found */\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce:  /x/ , noScriptRval: \"\\u96D4\", sourceIsLazy: true, catchTermination: x }));; return name in a0; }, hasOwn: function(name) { v2 = evalcx(\";\", g1);; return Object.prototype.hasOwnProperty.call(a0, name); }, get: function(receiver, name) { h1 = {};; return a0[name]; }, set: function(receiver, name, val) { g1.v1 = evalcx(\"/* no regression tests found */\", g1);; a0[name] = val; return true; }, iterate: function() { print(uneval(a0));; return (function() { for (var name in a0) { yield name; } })(); }, enumerate: function() { m2.get(p2);; var result = []; for (var name in a0) { result.push(name); }; return result; }, keys: function() { v2 = Object.prototype.isPrototypeOf.call(p0, g0.t0);; return Object.keys(a0); } }); }  } ");
/*fuzzSeed-248247344*/count=1455; tryItOut(" for each (w in {} = /*FARR*/[undefined, ...[], ].some -= 'fafafa'.replace(/a/g, true)) for each (\u3056 in 7 for (NaN of x) for each (e in /*FARR*/[])) for (x of (makeFinalizeObserver('tenured'))) for (x of /*MARR*/[-(2**53+2), null, null, -(2**53+2), null, false, null,  /x/ , false, -(2**53+2), -(2**53+2), null, -(2**53+2), -0, null, -0, -0, -(2**53+2), -0, -0, -(2**53+2),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ].map(decodeURI)) if (/*MARR*/[[], [],  /x/ ].map)");
/*fuzzSeed-248247344*/count=1456; tryItOut("var skfvqe = new SharedArrayBuffer(0); var skfvqe_0 = new Uint16Array(skfvqe); skfvqe_0[0] = 29; var skfvqe_1 = new Int32Array(skfvqe); print(skfvqe_1[0]); print(14);(undefined);");
/*fuzzSeed-248247344*/count=1457; tryItOut("/*hhh*/function jsxrbu(){neuter(this.b1, \"same-data\");}jsxrbu(delete x.x, (y) = \"\\u1C5F\"(({d: x }))\u000c);");
/*fuzzSeed-248247344*/count=1458; tryItOut("a1[o0.v2] = f0;");
/*fuzzSeed-248247344*/count=1459; tryItOut("h1.delete = Date.prototype.setUTCMilliseconds;");
/*fuzzSeed-248247344*/count=1460; tryItOut("\"use asm\"; with({y: x})t1[10];print(x);\nneuter(b0, \"change-data\");\n");
/*fuzzSeed-248247344*/count=1461; tryItOut("\"use strict\"; Array.prototype.splice.call(a0, NaN, v0);");
/*fuzzSeed-248247344*/count=1462; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.max(Math.fround(((Math.min(Math.trunc(Math.max(( + Math.min(Math.fround(( + Math.pow(( + y), -0x080000000))), ( + 2**53-2))), x)), ( + ( - Math.fround((Math.log10(( ! (Math.clz32(x) | 0))) | 0))))) >= (( ! Math.imul((42 | 0), x)) | 0)) | 0)), Math.fround(Math.fround(Math.tan(( ~ (x | 0))))))); }); ");
/*fuzzSeed-248247344*/count=1463; tryItOut("\"use strict\"; var v2 = g1.runOffThreadScript();");
/*fuzzSeed-248247344*/count=1464; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ( ~ Math.fround(( + Math.fround(((( + Math.log2(Math.fround((Math.fround((y << y)) ** Math.fround(x))))) >>> 0) && (Math.acos(( + x)) >>> 0)))))); }); testMathyFunction(mathy5, [(function(){return 0;}), 1, 0.1, objectEmulatingUndefined(), (new Boolean(true)), (new Number(0)), '', false, ({toString:function(){return '0';}}), -0, '0', '\\0', true, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), null, (new Boolean(false)), undefined, /0/, (new String('')), (new Number(-0)), '/0/', NaN, 0, [0], []]); ");
/*fuzzSeed-248247344*/count=1465; tryItOut("\"use strict\"; h1.keys = (function(j) { if (j) { try { v0 = a0.length; } catch(e0) { } try { m1.set(this.e0, (NaN = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: -21.keyFor, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: String.prototype.blink, hasOwn: function() { return false; }, get: function() { return undefined }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/ ), ({x: timeout(1800)}) !== (Int16Array(\"\u03a0\"))).eval(\"\\\"use strict\\\"; mathy4 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var atan = stdlib.Math.atan;\\n  var atan2 = stdlib.Math.atan2;\\n  var ff = foreign.ff;\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    {\\n      {\\n        d0 = (d0);\\n      }\\n    }\\n    d1 = (8796093022209.0);\\n    {\\n      {\\n        d0 = (+((d1)));\\n      }\\n    }\\n    d0 = (+/*FFI*/ff(((-((d1)))), ((((0x404b56be)-(0xbe7e035c)-((0x96c57064))) | (((Uint16ArrayView[2]))-(0x29e788d0)+(0x96e96e45)))), ((0x14e80a38)), ((Infinity)), ((((0xdc3ff6ae) % (((0xff226d9a))>>>((0x88deb21b))))|0)), ((Uint32ArrayView[(0x71905*(-0x8000000)) >> 2])), (((((0x0))) | (((0x7ae2ace7))))), ((((0xffffffff)) << ((-0x28b61b7)))), ((+(0xb5cda1f7))), ((65535.0)), ((-1.2089258196146292e+24))));\\n    {\\n      d0 = (d1);\\n    }\\n    {\\n      {\\n        d0 = (((+(1.0/0.0))) * ((+atan(((d0))))));\\n      }\\n    }\\n    (Uint16ArrayView[2]) = ((Uint32ArrayView[4096]));\\n    d1 = (((d0)) / ((+(-1.0/0.0))));\\n    d0 = (+(0.0/0.0));\\n    d0 = (+atan2(((d0)), ((d1))));\\n    switch ((0x5cf98110)) {\\n      default:\\n        {\\n          (Float64ArrayView[(-(0xfd51c233)) >> 3]) = ((d0));\\n        }\\n    }\\n    d1 = (d1);\\n    return +((d0));\\n  }\\n  return f; })(this, {ff: (function(x, y) { \\\"use strict\\\"; return (y == Math.atan2(Math.fround((Math.fround(x) << (Math.fround(y) ? x : x))), (((Math.fround(y) ? (x | 0) : (y | 0)) | 0) ? (x / Math.fround(x)) : y))); })}, new ArrayBuffer(4096)); \"))); } catch(e1) { } try { f1(f0); } catch(e2) { } m1.set(h0, h1); } else { try { g2.offThreadCompileScript(\"i0.next();\"); } catch(e0) { } try { /*ADP-1*/Object.defineProperty(g1.a1, 7, ({writable: (allocationMarker()), enumerable: \nthis})); } catch(e1) { } try { m0.has(eval(\"v0 = (t0 instanceof e2);\", let (b) \"\u03a0\")); } catch(e2) { } e2.add(s0); } });");
/*fuzzSeed-248247344*/count=1466; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(Math.max(( + Math.fround((Math.trunc((Math.imul(x, x) >>> 0)) >>> 0))), (Math.fround(y) != ( + x))), ((((Math.atan2(( ~ (( + ( ~ x)) == y)), Math.fround((mathy1(((( - (y >>> 0)) >>> 0) >>> 0), (Math.hypot(( + ( ! y)), x) >>> 0)) >>> 0))) >>> 0) | 0) << mathy0(( + Math.min((Number.MAX_SAFE_INTEGER ** y), 0x0ffffffff)), ( + Math.min(y, Math.sin((Math.hypot(( ! y), (y | 0)) | 0)))))) | 0)); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x100000001, 2**53, 0x0ffffffff, 2**53+2, 1/0, -0, -(2**53+2), 0x100000000, -0x080000000, -(2**53-2), -0x07fffffff, 0.000000000000001, 0/0, 0, -Number.MAX_SAFE_INTEGER, 0x080000000, 42, -0x080000001, 1, -Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -1/0, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-248247344*/count=1467; tryItOut("\"use strict\"; const get = new neuter(this, \"\u03a0\"), x = true, y, uzuteq, window, cayhrj, otteoi, z;v2 = t2.length;");
/*fuzzSeed-248247344*/count=1468; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ! Math.fround(Math.hypot(Math.fround((Math.imul((( + y) >>> 0), (x >>> 0)) >>> 0)), (Math.cbrt(((( + ( - (x | 0))) && (y | 0)) | 0)) >>> 0)))) | 0); }); ");
/*fuzzSeed-248247344*/count=1469; tryItOut("alizex, escrrm, d = x, x = [], gwwkpw, x, x;function f1(o0.i0)  { yield [[1]] } ");
/*fuzzSeed-248247344*/count=1470; tryItOut("/*RXUB*/var r = o2.o0.r0; var s = s1; print(s.split(r)); ");
/*fuzzSeed-248247344*/count=1471; tryItOut("/*infloop*/for(let x in ((eval)(this)\u0009))m2.set(e1, \"\\uBB8F\");");
/*fuzzSeed-248247344*/count=1472; tryItOut("\"use strict\"; Array.prototype.shift.call(o0.a1);");
/*fuzzSeed-248247344*/count=1473; tryItOut("testMathyFunction(mathy3, [1/0, 1, Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, 0x100000000, 0x080000001, 0x100000001, -0x0ffffffff, -0x100000000, 42, 0x07fffffff, 2**53-2, 2**53+2, 0/0, -(2**53-2), -(2**53), -Number.MIN_VALUE, Math.PI, -0x080000000, 0x080000000, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, -1/0, -Number.MIN_SAFE_INTEGER, 0, -0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0]); ");
/*fuzzSeed-248247344*/count=1474; tryItOut("{/*RXUB*/var r = /\\b/im; var s = \"\\n   \"; print(uneval(s.match(r))); \ng0.f1.toSource = (function() { for (var j=0;j<5;++j) { f0(j%2==0); } });\no2.m1.has(/*MARR*/[ /x/g , -0x0ffffffff,  /x/g ,  /x/ ,  \"\" ,  /x/g ,  /x/ , -0x0ffffffff,  /x/ ,  /x/g , -0x0ffffffff,  /x/g , -0x0ffffffff, -0x0ffffffff,  /x/g ,  /x/ ,  /x/ , -0x0ffffffff,  /x/ ,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/g ,  /x/ ,  /x/ ,  \"\" ,  \"\" , -0x0ffffffff,  /x/ ,  \"\" ,  /x/g , -0x0ffffffff,  \"\" ,  /x/ ,  \"\" ,  /x/ , -0x0ffffffff,  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/g ,  /x/g ,  /x/ ,  /x/ , -0x0ffffffff,  /x/g ,  /x/ ,  /x/g ,  /x/g ].map); }");
/*fuzzSeed-248247344*/count=1475; tryItOut("mathy3 = (function(x, y) { return ( ! ((( + Math.max(( + ( - y)), Math.imul(y, (Math.imul(( + y), (Math.imul((x >>> 0), x) >>> 0)) | 0)))) | 0) & Math.fround(Math.hypot(Math.fround(Math.fround(Math.hypot((Math.fround(y) ? x : ( ! Math.PI)), ( + ( + Math.tanh(( + y))))))), ( + Math.trunc(( ! y))))))); }); ");
/*fuzzSeed-248247344*/count=1476; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.atan2(((mathy2((mathy2(Number.MIN_VALUE, Math.fround(Math.cos(Math.fround(mathy0(x, 1.7976931348623157e308))))) | 0), Math.atan2(mathy0(Math.fround(y), Math.fround(x)), (x | 0))) % mathy2(Math.fround(( - (Number.MAX_VALUE >>> 0))), mathy1(y, ( + Math.min(Math.log1p((y | 0)), 1.7976931348623157e308))))) | 0), ( + ((Math.atan2(Math.log((Math.hypot((y >>> 0), (( - (( + (x | 0)) | 0)) >>> 0)) >>> 0)), Math.hypot((y | 0), (Math.imul(Math.fround(Math.log1p(((y * x) >>> 0))), (( + Math.pow(Math.fround(y), 0x080000000)) | 0)) | 0))) >>> 0) <= (( ~ x) | 0))))); }); ");
/*fuzzSeed-248247344*/count=1477; tryItOut("\"use asm\"; h2.getPropertyDescriptor = g0.f1;");
/*fuzzSeed-248247344*/count=1478; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d1));\n  }\n  return f; })(this, {ff:  \"\" }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, -0x07fffffff, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, -0x100000000, -(2**53-2), 1/0, -Number.MIN_VALUE, 2**53-2, -0, 0x100000001, 2**53, 0x0ffffffff, -(2**53), -1/0, 1.7976931348623157e308, -0x0ffffffff, 0x080000001, -(2**53+2), 1, -0x080000001, 0, Number.MAX_SAFE_INTEGER, 0x080000000, 42, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-248247344*/count=1479; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((((Math.fround(( ! (mathy0((y >>> 0), y) | 0))) | 0) ^ Math.fround(Math.fround(Math.asinh(Math.min(Math.abs(Math.fround(Math.clz32(y))), x))))) | 0) >>> 0) ? (Math.log1p(( ! Math.min(Math.fround((mathy0(((mathy0((-0x0ffffffff >>> 0), ( + y)) >>> 0) | 0), (Math.PI | 0)) | 0)), Math.fround(42)))) >>> 0) : (Math.log1p((mathy0(Math.fround(0x07fffffff), Math.fround(( + Math.fround(Math.fround(( + ((x < Math.fround((mathy0((y | 0), (y | 0)) | 0))) | 0))))))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0x100000001, 1.7976931348623157e308, -0x0ffffffff, -0x080000001, -Number.MIN_VALUE, Math.PI, 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 0x080000000, 42, -(2**53+2), 1, 0x07fffffff, 0x0ffffffff, 2**53+2, -Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, -1/0, 2**53-2, -(2**53), 0/0, -0x07fffffff, -0x080000000, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=1480; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1481; tryItOut("v2 = this.a0[\"toString\"];");
/*fuzzSeed-248247344*/count=1482; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.atan(Math.pow(( + (Math.imul(( + Math.pow(x, (( ! Math.fround(Math.cosh(Math.fround(mathy1((0/0 >>> 0), -Number.MAX_VALUE))))) | 0))), (Math.fround((((y ? mathy0(y, Number.MAX_SAFE_INTEGER) : x) ** (y | 0)) != Math.fround(( - (Math.hypot((x | 0), ( + 42)) | 0))))) >>> 0)) >>> 0)), Math.fround(Math.imul(Math.fround((Math.min(Math.round(Math.max(x, -0x0ffffffff)), -0x100000001) || (x ^ x))), Math.fround(mathy1(Math.fround((-Number.MIN_SAFE_INTEGER <= 0)), (Math.atan((0x100000000 | 0)) | 0))))))); }); testMathyFunction(mathy2, [-0x07fffffff, 1/0, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, -(2**53), -(2**53-2), 2**53+2, -0x100000001, 0x080000001, 0x100000000, 0x100000001, -0x0ffffffff, 0x080000000, 0/0, 42, Number.MAX_VALUE, -0x080000000, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, -(2**53+2), -1/0]); ");
/*fuzzSeed-248247344*/count=1483; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.ceil(Math.expm1(Math.expm1(( + (( + ( - y)) ? y : 0x100000001))))); }); testMathyFunction(mathy3, [-0x100000001, 0x100000000, Number.MAX_VALUE, 42, -(2**53+2), 0.000000000000001, -0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0x080000000, -(2**53-2), -0x0ffffffff, 0, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, 1, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, 0x0ffffffff, 2**53, 0x07fffffff, -Number.MIN_VALUE, -0, 1.7976931348623157e308, -1/0, 1/0, Math.PI, Number.MIN_VALUE]); ");
/*fuzzSeed-248247344*/count=1484; tryItOut("m0.get(h0);");
/*fuzzSeed-248247344*/count=1485; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ ( ! ( + (((x >>> 0) & (( ~ 1.7976931348623157e308) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x080000000, -(2**53), 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -0, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 1/0, Number.MIN_VALUE, 0x07fffffff, 2**53-2, 2**53, 0x100000001, -0x080000001, -0x0ffffffff, 42, -(2**53+2), 0x080000000, 0, 0x080000001, -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=1486; tryItOut("Array.prototype.forEach.apply(a0, [(function mcc_() { var blrnsx = 0; return function() { ++blrnsx; if (/*ICCD*/blrnsx % 4 != 1) { dumpln('hit!'); try { t0 = this.t2.subarray(({valueOf: function() { for (var p in i1) { try { g1.m0.set(b2, s1); } catch(e0) { } try { this.m2.get(t0); } catch(e1) { } v0.toSource = (function() { for (var j=0;j<1;++j) { f1(j%4==1); } }); }return 19; }})); } catch(e0) { } try { g0.e1.delete(this.g1); } catch(e1) { } v2 = g2.eval(\"break L;\\nprint(x);\\n\"); } else { dumpln('miss!'); try { ; } catch(e0) { } try { v0 = evaluate(\"\\\"use strict\\\"; {v1 = new Number(h2);print(x); }\", ({ global: g0.g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 37 == 9), sourceIsLazy: false, catchTermination: (x % 5 != 0) })); } catch(e1) { } try { M:for(var d = OSRExit((this.__defineGetter__(\"b\", Uint8Array))) in  \"\" ) {m0.get(x);var mlxnwl = new SharedArrayBuffer(4); var mlxnwl_0 = new Float32Array(mlxnwl); mlxnwl_0[0] = -24; DataView.prototype.getUint32 } } catch(e2) { } t2 = new Float32Array(a1); } };})(), b1]);");
/*fuzzSeed-248247344*/count=1487; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( ~ ( + (Math.atan2(Math.fround(((Math.hypot(Math.cosh(( + ( ! ( + (y !== (x >>> 0)))))), x) >>> 0) >>> x)), ((Math.pow(((( + Math.fround(Math.log(Math.fround((Math.max(Math.atan2((x >>> 0), (y >>> 0)), (x | 0)) | 0))))) ^ Math.fround(( ~ x))) | 0), ((( ~ y) >>> 0) | 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy0, /*MARR*/[[], [], [], (0/0), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], (0/0), [], (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), [], [], (0/0), [], (0/0), (0/0), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], (0/0), (0/0), (0/0), (0/0), (0/0), [], [], (0/0), [], (0/0), [], (0/0), [], (0/0), (0/0), (0/0), (0/0), [], (0/0), (0/0), [], [], (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), [], [], (0/0), [], (0/0), (0/0), (0/0), [], (0/0)]); ");
/*fuzzSeed-248247344*/count=1488; tryItOut("( '' );");
/*fuzzSeed-248247344*/count=1489; tryItOut("h1 + '';");
/*fuzzSeed-248247344*/count=1490; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53, 0.000000000000001, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 0x080000001, Number.MIN_VALUE, 0x080000000, -(2**53-2), Number.MAX_VALUE, -0x100000001, -(2**53), 0x07fffffff, -0x080000001, 0, Math.PI, 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, 0/0, 1, 2**53+2, -(2**53+2), 1/0, -Number.MAX_VALUE, -0]); ");
/*fuzzSeed-248247344*/count=1491; tryItOut("\"use strict\"; e2 = new Set(o2);");
/*fuzzSeed-248247344*/count=1492; tryItOut("\"use asm\"; this.v1 = evaluate(\"t0.set(t0, 7);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: (x) = this }));");
/*fuzzSeed-248247344*/count=1493; tryItOut("");
/*fuzzSeed-248247344*/count=1494; tryItOut("\"use strict\"; var cbyjzz = new ArrayBuffer(0); var cbyjzz_0 = new Float32Array(cbyjzz); cbyjzz_0[0] = -11; Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-248247344*/count=1495; tryItOut("mathy3 = (function(x, y) { return mathy0(( + (mathy2(( ! (Math.fround(( + Math.fround((( + (x | 0)) | 0)))) >>> 0)), Math.round(((y >>> 0) ^ y))) | 0)), Math.max(Math.cos(Math.asin(( + x))), (((( + ( - ( + y))) | 0) ? ((Math.exp(y) < (-(2**53-2) >>> 0)) | 0) : (Math.fround(( ! Math.fround(x))) | 0)) | 0))); }); testMathyFunction(mathy3, /*MARR*/[true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), true]); ");
/*fuzzSeed-248247344*/count=1496; tryItOut("eval = x, x = \"\\uA827\", ekfenu;continue ;");
/*fuzzSeed-248247344*/count=1497; tryItOut("testMathyFunction(mathy4, [2**53-2, 0x07fffffff, 0x080000001, -0x100000001, 42, 0.000000000000001, -(2**53-2), 0x100000001, Math.PI, -0x100000000, 2**53, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 1, 1.7976931348623157e308, 0x080000000, -0x080000000, 0, -0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x07fffffff, -1/0, -0]); ");
/*fuzzSeed-248247344*/count=1498; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.cosh(Math.imul((Math.fround(y) ? Math.fround(mathy2(Math.imul(y, x), ( + x))) : Math.fround(Math.min(( ~ -Number.MAX_VALUE), Math.pow(0/0, x)))), Math.atan2((Math.atan2(mathy2(Math.fround(Math.imul(Math.fround(y), Math.fround(y))), ( + y)), 0x080000000) >>> 0), (((y | 0) / y) | 0)))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x07fffffff, 0x080000000, -(2**53-2), 0.000000000000001, -0x100000000, 0x080000001, -0x080000001, 2**53+2, -(2**53+2), 0x100000000, -0x0ffffffff, 0/0, 2**53-2, -1/0, Number.MIN_SAFE_INTEGER, -0, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 42, -(2**53), Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, -Number.MAX_VALUE, 0, Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-248247344*/count=1499; tryItOut("mathy1 = (function(x, y) { return Math.atanh(Math.fround(( + Math.fround(Math.fround(Math.log1p(Math.fround(( ! (((( + ( ~ ( + y))) >>> 0) * (y >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy1, [2**53+2, -0x0ffffffff, -1/0, 0/0, -Number.MIN_VALUE, -0x07fffffff, 2**53-2, 1/0, -(2**53-2), 0x100000001, Math.PI, -0x100000001, -0, -0x100000000, 0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 2**53, -(2**53+2), 0, Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-248247344*/count=1500; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround(Math.hypot(((mathy3((( ! ( + x)) >>> 0), ((Math.fround(Math.trunc(-0x100000001)) << y) >>> 0)) | 0) | 0), ((( ~ ( + x)) >>> 0) | 0))), ((x * ( - Math.fround(( ! ( + x))))) & ( + ((((( + y) % (y >>> 0)) != y) | 0) & ((((x >>> 0) ? (x >>> 0) : ((((x | 0) === (0 | 0)) >>> 0) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy4, [2**53-2, -1/0, 1/0, -0x100000001, 0x080000000, 0x100000001, -(2**53-2), -0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), 0, 0/0, 0x080000001, 0x0ffffffff, 2**53+2, -0x100000000, 0.000000000000001, 42, 1, -0, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1501; tryItOut("mathy0 = (function(x, y) { return Math.atan((Math.fround(Math.hypot(Math.fround((y + ( + ( - x)))), Math.fround(( ! Math.fround((y > Math.fround((Math.pow((y >>> 0), ( + Number.MIN_VALUE)) >>> 0)))))))) <= ( ~ (( + x) != ( + Number.MAX_SAFE_INTEGER))))); }); testMathyFunction(mathy0, [-0x080000000, Number.MIN_SAFE_INTEGER, 1/0, 0/0, 1, 0x100000001, -(2**53), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), -Number.MIN_VALUE, -0, 1.7976931348623157e308, -1/0, 2**53-2, -0x100000000, 0x080000000, 2**53, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 2**53+2, -0x080000001, Math.PI, 0x0ffffffff, 0, 0x080000001, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1502; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1503; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.log2(( ~ Math.fround((( + ( + Math.hypot(( + y), ( + ( ! x))))) | 0)))) | 0); }); testMathyFunction(mathy0, [0, -(2**53+2), -0x080000000, 0/0, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, -0x07fffffff, -0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 42, -(2**53-2), Number.MAX_VALUE, 0x100000000, 0x080000001, 0x07fffffff, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, -0, 1/0, 1, -0x100000001, 0x100000001, 0x080000000]); ");
/*fuzzSeed-248247344*/count=1504; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\1\", \"gyim\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=1505; tryItOut("m1 + '';");
/*fuzzSeed-248247344*/count=1506; tryItOut("v0 = (o0.p2 instanceof a1);");
/*fuzzSeed-248247344*/count=1507; tryItOut("Array.prototype.forEach.apply(a1, [Int32Array.bind(this.b1), i2, ((\ny - -18.fixed((Math.log2(-13)), (4277)))) = [, ] = x, t1, s2]);");
/*fuzzSeed-248247344*/count=1508; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1509; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( + Math.hypot(( + Math.max(x, ( + Math.cosh(( + ((Math.fround(( ! Math.expm1(x))) >>> 0) + mathy2(x, 0/0))))))), ( + Math.cbrt(x))))) / Math.fround(((Math.max((((y >>> 0) > (Math.min(( + Math.log1p(y)), y) >>> 0)) >>> 0), ( - ( + mathy3(Math.round(Math.fround(mathy1(y, x))), Math.fround(mathy2(Math.fround(y), Math.fround(-0))))))) ? Math.log(Math.atan2((2**53+2 >>> 0), (Math.log10(Math.fround(Math.pow(Math.fround(0x080000001), Math.fround(y)))) >>> 0))) : (Math.hypot((( ! ( + y)) | 0), (( + ( ! ( + (Math.atan(-0x07fffffff) | 0)))) | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy4, [0.000000000000001, -0x100000000, 1, 0x07fffffff, -(2**53+2), -0x0ffffffff, -0x100000001, -0, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, -(2**53), Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0, 0x0ffffffff, 2**53+2, -0x080000000, -1/0, 2**53, 0x080000001, 0/0, 42, 1/0, -Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1510; tryItOut("let (jdycii, c, x = (4277), {} = /*MARR*/[(1/0), (1/0), (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), (1/0), (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0), (1/0), /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, /(?!((?:(?:\\D)))|(?:.[^]*?)|([\\0\u46b7\\u002b]))+?/, (1/0)].filter, NaN = e = (4277) /  /x/ ) { /* no regression tests found */ }");
/*fuzzSeed-248247344*/count=1511; tryItOut("{ void 0; abortgc(); }");
/*fuzzSeed-248247344*/count=1512; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, 0.000000000000001, 42, -0x0ffffffff, Math.PI, 1/0, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, 1, 2**53, -0x07fffffff, 1.7976931348623157e308, -(2**53), Number.MIN_VALUE, 2**53-2, 0x07fffffff, -0x100000000, 0/0, -(2**53-2), Number.MAX_VALUE, 0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1513; tryItOut("\"use strict\"; s2 + '';");
/*fuzzSeed-248247344*/count=1514; tryItOut("\"use strict\"; print(a%=[,,z1]);for (var v of t2) { try { m2.delete(a0); } catch(e0) { } try { Array.prototype.shift.apply(a0, []); } catch(e1) { } a0.push(m0, g1, o2, o1.b0); }");
/*fuzzSeed-248247344*/count=1515; tryItOut("\"use strict\"; /*MXX2*/g2.Symbol.name = i1;");
/*fuzzSeed-248247344*/count=1516; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((Math.pow(x, Math.cosh((Math.atan2(x, -Number.MAX_VALUE) | 0))) >>> 0) != ( - Math.hypot(-(2**53), Math.imul((( ~ y) | 0), ( + x))))) !== ( + ( + Math.hypot(((Math.fround(( + Math.fround(( ~ Math.fround(y))))) >> ((((x >>> 0) >= x) >>> 0) >>> -Number.MIN_SAFE_INTEGER)) >>> 0), ((y ? (x | 0) : ( + Math.max(x, Math.imul(y, x)))) | 0))))); }); testMathyFunction(mathy0, [-0x080000000, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, 2**53-2, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -(2**53), -Number.MIN_VALUE, 0/0, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, 0x100000000, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, 0x100000001, 42, -1/0, 1, 0x080000000, -(2**53+2), 2**53+2, -0x080000001]); ");
/*fuzzSeed-248247344*/count=1517; tryItOut("o0.v2 = Object.prototype.isPrototypeOf.call(this.g2, g0.i1);");
/*fuzzSeed-248247344*/count=1518; tryItOut("t2 = new Int16Array(b0, 12, 10);");
/*fuzzSeed-248247344*/count=1519; tryItOut("mathy5 = (function(x, y) { return Math.fround(mathy3(Math.fround(( + ( ~ ( + mathy3(( + (mathy2(( + x), ( + Math.atan(Math.fround((Math.hypot((y >>> 0), Math.log1p(x)) >>> 0))))) | 0)), mathy0(Math.atanh(y), 2**53-2)))))), Math.fround(( + Math.fround(mathy0(Math.fround(Math.cbrt(Math.fround(( + ( ~ Math.fround(mathy2((Number.MIN_SAFE_INTEGER >>> 0), (Math.atan2(2**53+2, y) | 0)))))))), (Math.fround(mathy2(( + Math.sign([])), Math.min(( + mathy1(( + x), ( + x))), ( ! Math.pow(y, y))))) >>> 0))))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, 0x100000000, 0/0, Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -0x080000001, 1, Number.MAX_VALUE, -0, 2**53-2, 2**53+2, 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, -(2**53-2), -1/0, -0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53), 0x080000001, -Number.MIN_VALUE, Math.PI, 0x080000000, 0.000000000000001, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1520; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float64ArrayView[1]) = ((d1));\n    return ((-(i0)))|0;\n  }\n  return f; })(this, {ff: ({} = arguments << arguments)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_VALUE, -0, -(2**53+2), -0x100000001, 1.7976931348623157e308, 2**53+2, 42, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, 0x07fffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 0, -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), 1, Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 2**53, 0x0ffffffff, -(2**53-2), 2**53-2, 0x100000000, 0/0, 0x100000001]); ");
/*fuzzSeed-248247344*/count=1521; tryItOut("\"use strict\"; t2[15] = (new (function(y) { \"use strict\"; return \"\\uF57C\" })());");
/*fuzzSeed-248247344*/count=1522; tryItOut("\"use strict\"; a0.push(f0, e0, this.a1, t1);");
/*fuzzSeed-248247344*/count=1523; tryItOut("a2[({valueOf: function() { /*bLoop*/for (var sxbqak = 0; sxbqak < 122; ++sxbqak) { if (sxbqak % 5 == 1) { o0.valueOf = (Int8Array).bind;t0.set(a1, 10); } else { var vevayl = new ArrayBuffer(0); var vevayl_0 = new Uint8Array(vevayl); print(vevayl_0[0]); /*RXUB*/var r = vevayl_0[7]; var s = \"a\"; print(s.match(r)); print(r.lastIndex); print(x); }  } return 1; }})];");
/*fuzzSeed-248247344*/count=1524; tryItOut("/*RXUB*/var r = null; var s = eval; print(uneval(r.exec(s))); ");
/*fuzzSeed-248247344*/count=1525; tryItOut("\"use strict\"; this.v2 = Object.prototype.isPrototypeOf.call(o0, g1.p1);");
/*fuzzSeed-248247344*/count=1526; tryItOut("mathy2 = (function(x, y) { return (Math.atan2(Math.fround(Math.exp(((((Math.max(((-Number.MIN_VALUE ? x : (y % (y | 0))) >>> 0), y) >>> 0) != ((mathy1(Math.fround(0x100000001), Math.fround(Math.tanh(-(2**53+2)))) | 0) | 0)) + 42) >>> 0))), Math.fround((( + ( + Math.atan(( + (Math.hypot(Math.fround(( + Math.fround(x))), (y | 0)) | 0))))) >>> 0))) | 0); }); testMathyFunction(mathy2, [2**53, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x100000001, 0/0, -0x100000000, 1, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0x080000000, -1/0, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, 1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, Number.MAX_VALUE, -(2**53+2), 0.000000000000001, -(2**53), 1.7976931348623157e308, -0, -(2**53-2), 42, 0, Math.PI]); ");
/*fuzzSeed-248247344*/count=1527; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.tan(((-0x0ffffffff >> (Math.sinh((x | 0)) | 0)) >>> 0)) >>> 0) >>> Math.fround(Math.acos(Math.fround(( + Math.min(x, (Math.fround(( - (Math.max((Math.max(Math.fround(x), Math.fround(y)) | 0), (y | 0)) | 0))) | 0))))))); }); testMathyFunction(mathy2, [0.000000000000001, 1/0, -(2**53+2), 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, 0x080000001, -0x100000000, -Number.MIN_VALUE, -0x100000001, -1/0, -Number.MAX_VALUE, 0x100000001, 2**53, 0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 0/0, -0x0ffffffff, -(2**53), Number.MIN_VALUE, -0, Math.PI, 0, -(2**53-2), 2**53-2, -0x080000000, 1]); ");
/*fuzzSeed-248247344*/count=1528; tryItOut("{f1 = (function(j) { if (j) { try { Array.prototype.pop.call(a2, v1, s1); } catch(e0) { } try { e0.add(t0); } catch(e1) { } o0.__iterator__ = (function mcc_() { var wknwhj = 0; return function() { ++wknwhj; if (/*ICCD*/wknwhj % 9 != 3) { dumpln('hit!'); for (var v of h0) { Object.prototype.watch.call(t2, \"apply\", (function() { (void schedulegc(g2)); return t2; })); } } else { dumpln('miss!'); for (var p in t0) { try { /*RXUB*/var r = r1; var s = \"a\\u0098a\\u0098\"; print(uneval(s.match(r)));  } catch(e0) { } try { i1 = x; } catch(e1) { } e1.add(o1); } } };})(); } else { try { m2.get( /x/ ); } catch(e0) { } try { m1 + ''; } catch(e1) { } try { h1 + ''; } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(o0, this.g2.o2); } }); }");
/*fuzzSeed-248247344*/count=1529; tryItOut("o1.p1.__iterator__ = (function() { try { Array.prototype.shift.apply(a0, []); } catch(e0) { } try { o1.m2 = new Map; } catch(e1) { } g0 + ''; return h1; });");
/*fuzzSeed-248247344*/count=1530; tryItOut("s2 += s0;");
/*fuzzSeed-248247344*/count=1531; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-248247344*/count=1532; tryItOut("print(x);");
/*fuzzSeed-248247344*/count=1533; tryItOut("/*bLoop*/for (blrmko = 0; blrmko < 21; ++blrmko) { if (blrmko % 4 == 0) { var e = undefined(Math.sign(2),  \"\" );{o2.toString = f2; } } else { v0 = o1.t0.length; }  } ");
/*fuzzSeed-248247344*/count=1534; tryItOut("L:if(offThreadCompileScript) { if (x = [,,]) {/* no regression tests found */ } else o0.v0 = (g2.i0 instanceof f0);}");
/*fuzzSeed-248247344*/count=1535; tryItOut("\"use strict\"; s0 + a0;");
/*fuzzSeed-248247344*/count=1536; tryItOut("const v2 = o2.g1.g1.runOffThreadScript();");
/*fuzzSeed-248247344*/count=1537; tryItOut("Array.prototype.splice.apply(o0.o1.a1, [-6, 18]);");
/*fuzzSeed-248247344*/count=1538; tryItOut("testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 0/0, Number.MIN_VALUE, -0x0ffffffff, 1, 0, -(2**53+2), -(2**53-2), -0, -0x080000001, 42, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), -0x100000001, -1/0, 0x100000001, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, Math.PI, 0x080000001, -0x080000000, -0x100000000]); ");
/*fuzzSeed-248247344*/count=1539; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.clz32((( ~ Math.min(( + (Math.atan((x | 0)) >>> Math.log2(y))), (( + Math.sin(y)) | 0))) | 0))); }); testMathyFunction(mathy5, /*MARR*/[x = (Function).call.prototype, x = (Function).call.prototype, objectEmulatingUndefined(), -Infinity, -Infinity, x = (Function).call.prototype, ['z'], x = (Function).call.prototype, true, true, objectEmulatingUndefined(), ['z'], ['z'], true, true, true]); ");
/*fuzzSeed-248247344*/count=1540; tryItOut("/* no regression tests found */L:for(a in ((neuter)((yield \"\\uA790\").throw(14)))){print((y.yoyo((function ([y]) { })()).yoyo(a)));m2.delete(m2); }");
/*fuzzSeed-248247344*/count=1541; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-248247344*/count=1542; tryItOut("mathy1 = (function(x, y) { return ( + (( + ( ~ Math.fround(Math.min(Math.fround(Math.sinh(mathy0(y, ( + Math.max(Math.fround((( + y) >>> 0)), Math.fround(-0x100000000)))))), ( + (( + x) ^ ( + y))))))) | ( + Math.asinh(Math.acosh(( + Math.imul(( + Math.min(Math.fround((Math.acosh(x) + x)), y)), y))))))); }); testMathyFunction(mathy1, [-0x080000000, 0, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, 42, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, Math.PI, -(2**53-2), -0, Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -(2**53+2), 0x080000000, -0x080000001, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, -0x100000001, 1, 2**53+2, 0/0]); ");
/*fuzzSeed-248247344*/count=1543; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(Math.round(Math.fround(Math.fround(Math.pow(mathy1((( + (x | 0)) | 0), ( ! 0x100000001)), (( + ( - ( + y))) ? ( + mathy1(( + ( - x)), ( + x))) : Math.fround(Math.fround(Math.min(Math.fround((x + (2**53-2 | 0))), x))))))))) % mathy1(Math.tanh(x), (((Math.log1p(((Number.MIN_VALUE >= y) >>> 0)) >>> 0) ** Math.abs(y)) | 0))); }); testMathyFunction(mathy3, /*MARR*/[x, new String(''), x, x, x, new String(''), new String(''), x, x, new String(''), x, new String(''), new String(''), new String(''), x, x, x, x, new String(''), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String(''), new String(''), x, x, new String(''), x, x, x, new String(''), x, x, new String(''), x, x, x, new String(''), x, new String(''), x, x, x, x, x, x, x, x, x, x, x, x, x, new String(''), x, x, new String(''), x, new String(''), new String(''), x, new String(''), new String(''), new String('')]); ");
/*fuzzSeed-248247344*/count=1544; tryItOut("do {(window);switch(x) { default: break; case this:  } } while((/*UUV1*/(e.isExtensible = arguments.callee)) && 0);");
/*fuzzSeed-248247344*/count=1545; tryItOut("\"use strict\"; testMathyFunction(mathy2, [(new Number(0)), 1, (new String('')), 0.1, 0, (new Boolean(true)), objectEmulatingUndefined(), (function(){return 0;}), '', -0, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), [], '\\0', '/0/', false, true, '0', /0/, (new Number(-0)), null, NaN, ({valueOf:function(){return 0;}}), (new Boolean(false)), [0], undefined]); ");
/*fuzzSeed-248247344*/count=1546; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.sqrt((( + Math.tan(( + ( + ( + ( + ( - x))))))) | 0)); }); testMathyFunction(mathy0, [-0x080000001, -0, -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, 42, 1, 0/0, -0x07fffffff, 0x080000001, -0x100000000, -0x100000001, -Number.MAX_VALUE, 0x080000000, -(2**53), 0x0ffffffff, -(2**53-2), Math.PI, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 0x100000001, 0, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1547; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a0, [TypeError.prototype.toString.bind(e0), a1]);");
/*fuzzSeed-248247344*/count=1548; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min(((-Number.MIN_VALUE ? (( ~ (y && y)) | 0) : x) ** ((Math.fround(mathy0((((x | 0) ? ((Math.hypot((x >>> 0), 1) >>> 0) | 0) : (y | 0)) | 0), 0x07fffffff)) && (mathy2((Math.trunc(x) >>> 0), (y >>> 0)) >>> 0)) | 0)), (Math.fround(Math.imul(( ~ x), Math.fround(Math.log(( - x))))) ** Math.sign((x | 0)))); }); testMathyFunction(mathy5, [Math.PI, -Number.MIN_VALUE, -0, -(2**53+2), 0/0, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -0x080000000, Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0x100000001, 0, 0x080000000, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, -(2**53-2), 2**53-2, 2**53+2, 1/0, 0.000000000000001, 1, -0x100000000, 2**53, -(2**53), 42, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-248247344*/count=1549; tryItOut("let (w) { for (var v of f1) { t2[({valueOf: function() { (this);return 4; }})] = window; }let y = ((function too_much_recursion(owuzws) { ; if (owuzws > 0) { ; too_much_recursion(owuzws - 1);  } else {  }  })(3)); }");
/*fuzzSeed-248247344*/count=1550; tryItOut("/*tLoop*/for (let e of /*MARR*/[new String(''), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0),  /x/g ]) { o2.v2 = Object.prototype.isPrototypeOf.call(t1, s0); }");
/*fuzzSeed-248247344*/count=1551; tryItOut("o1 = x;");
/*fuzzSeed-248247344*/count=1552; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-248247344*/count=1553; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return (Math.asinh((((((((((Math.atan2(Math.fround(((Math.hypot(x, (0x080000001 | 0)) | 0) | x)), Math.fround(Math.tan(( + x)))) | 0) % (Math.abs((Math.fround(Math.hypot((x >>> 0), y)) | 0)) | 0)) | 0) << Math.hypot(x, Math.atan2(x, 0/0))) >>> 0) | 0) | ((Math.fround(Math.atan2(Math.fround(x), ( ~ -0x080000000))) >= (( ~ Math.fround((Math.sinh(((0.000000000000001 ? Math.cos(y) : ( + (( + -(2**53+2)) * -0))) | 0)) | 0))) | 0)) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy0, [-(2**53), Number.MAX_VALUE, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 1, -1/0, -(2**53-2), 0x080000000, 0x100000000, -0x100000000, 0.000000000000001, -0x07fffffff, 2**53-2, 0, 0x100000001, 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, -Number.MAX_VALUE, 0/0, 0x080000001, 0x0ffffffff, -0x0ffffffff, -0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), 0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1554; tryItOut("\"use strict\"; for (var v of h2) { try { a1 = []; } catch(e0) { } s1 += g2.s2; }");
/*fuzzSeed-248247344*/count=1555; tryItOut("v0 = g2.g1.eval(\"/* no regression tests found */\");");
/*fuzzSeed-248247344*/count=1556; tryItOut("mathy2 = (function(x, y) { return ( ! ( + Math.atanh(((Math.acosh(Math.fround((( + (Math.asin((2**53-2 >> y)) >>> 0)) >= y))) | 0) | 0)))); }); testMathyFunction(mathy2, [[], NaN, ({valueOf:function(){return 0;}}), '0', 0, '\\0', true, ({toString:function(){return '0';}}), false, undefined, '', /0/, objectEmulatingUndefined(), (new Number(-0)), ({valueOf:function(){return '0';}}), (new Boolean(false)), (new String('')), (new Number(0)), 1, 0.1, '/0/', null, -0, (new Boolean(true)), [0], (function(){return 0;})]); ");
/*fuzzSeed-248247344*/count=1557; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?=(?:[^\\\\w\\\\0-\\\\x3C\\u241d\\ud33d])+($)))\", \"gi\"); var s = \"\\n\\n\\n\\n%\\n\\n\\n\"; print(s.match(r)); ");
/*fuzzSeed-248247344*/count=1558; tryItOut("\"use strict\"; h0.getPropertyDescriptor = (function() { v0 = t2.length; return p1; });");
/*fuzzSeed-248247344*/count=1559; tryItOut("\"use strict\"; for(let d = (makeFinalizeObserver('tenured')) in  '' ) print(((x =  ''  <= /(?:(?:(?=\\)){0})|(?!(?:(?:\\B)))/gyi)));");
/*fuzzSeed-248247344*/count=1560; tryItOut("\"\\uD052\";\nm0.has(this.h2);\n");
/*fuzzSeed-248247344*/count=1561; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( ~ ( + Math.pow(( + mathy3(y, (((Math.hypot(x, Math.fround(Math.fround(Math.trunc(Math.fround(x))))) >>> 0) ? (0x080000001 >>> 0) : (x >>> 0)) >>> 0))), ( + y)))) & ( + (( + mathy0(( ! ( + Math.log10((x ? Math.pow(y, x) : y)))), ( + ( - (((y | 0) % y) | 0))))) , ( ~ Math.fround((Math.imul((Math.max((-1/0 >>> 0), x) | 0), x) | 0)))))) >>> 0); }); ");
/*fuzzSeed-248247344*/count=1562; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround(((( + ( + ((Math.max(x, y) >>> 0) | y))) >>> 0) >>> ( - (Math.atan2(y, (( - 0x100000000) | 0)) | 0))))); }); testMathyFunction(mathy5, [1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -(2**53), 0x100000001, -(2**53+2), 2**53+2, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), -1/0, -0x100000000, 2**53-2, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, Math.PI, 0.000000000000001, 0x080000001, 0x100000000, 1, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, 2**53, 1.7976931348623157e308, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-248247344*/count=1563; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n;    return +((131073.0));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [2**53+2, 42, 0.000000000000001, -(2**53), 0/0, -0x100000000, Number.MAX_VALUE, 2**53-2, -(2**53+2), -0x080000000, -0, -0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, 0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, Math.PI, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, -1/0, 2**53]); ");
/*fuzzSeed-248247344*/count=1564; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul(((mathy4(y, Math.imul((Math.hypot(y, x) <= y), Math.fround(y))) || (mathy4(((Math.log2((y >>> 0)) >>> 0) >>> 0), (Math.hypot(( + (mathy2((-0 >>> 0), ((Math.min(y, x) >>> 0) >>> 0)) >>> 0)), -0x07fffffff) | 0)) >>> 0)) | 0), Math.min(( + Math.imul(x, y)), Math.tanh(Math.max((x | 0), (Math.max(x, y) | 0))))); }); ");
/*fuzzSeed-248247344*/count=1565; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - Math.fround((Math.fround(( ! (y | 0))) | Math.fround(Math.pow((( - (Math.pow(y, -0x07fffffff) >>> 0)) >>> 0), x))))) >= Math.fround(( ~ Math.fround(Math.fround((Math.fround(( + mathy3((Number.MIN_VALUE >>> 0), ((x || ( + Number.MIN_SAFE_INTEGER)) >>> 0)))) ? (y >>> 0) : Math.fround(Math.ceil(Math.log((Math.cbrt((y >>> 0)) >>> 0)))))))))); }); testMathyFunction(mathy5, [0.000000000000001, Math.PI, -0x080000000, -0x07fffffff, -(2**53-2), -0, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0x080000001, 1/0, -0x080000001, 0/0, 0x100000000, -Number.MIN_VALUE, 2**53-2, 0x080000000, 0x100000001, -0x100000001, -(2**53), 0x07fffffff, 0x0ffffffff, 2**53, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 1, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=1566; tryItOut("");
/*fuzzSeed-248247344*/count=1567; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - Math.atan2(Math.fround((Math.fround(2**53-2) << Math.sin(Math.max((x >>> 0), (( ! (x >>> 0)) >>> 0))))), ( - Math.clz32((( ! (x >>> 0)) | 0))))); }); testMathyFunction(mathy5, [(function(){return 0;}), '\\0', NaN, true, (new Boolean(false)), (new Boolean(true)), 0.1, -0, null, (new String('')), /0/, '', ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), 1, undefined, (new Number(0)), (new Number(-0)), '0', false, ({valueOf:function(){return 0;}}), '/0/', objectEmulatingUndefined(), [0], 0, []]); ");
/*fuzzSeed-248247344*/count=1568; tryItOut("p0 + '';");
/*fuzzSeed-248247344*/count=1569; tryItOut("Array.prototype.sort.apply(a2, [f2, ]);");
/*fuzzSeed-248247344*/count=1570; tryItOut("selectforgc(o1);");
/*fuzzSeed-248247344*/count=1571; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.pow(( + Math.hypot(Math.max((y | 0), (((-Number.MAX_SAFE_INTEGER | 0) || (x | 0)) | 0)), ( + mathy0((mathy0(((x > (0x080000001 | 0)) >>> 0), Math.fround(mathy0(0x080000000, -0x100000000))) >>> 0), Math.cosh((x ? (Math.pow(-(2**53-2), y) | 0) : y)))))), Math.round(Math.expm1((Math.fround((mathy1(y, (y ? y : y)) | 0)) | 0)))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000, 0, 0x100000000, -1/0, -(2**53-2), Number.MAX_VALUE, 1/0, 2**53, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 0x080000001, 0x0ffffffff, -0, 0/0, -0x100000001, Math.PI, -0x080000000, -0x100000000, 42, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001]); ");
/*fuzzSeed-248247344*/count=1572; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((((/*FFI*/ff(((((((-2097153.0)) % ((295147905179352830000.0)))) % (((Float64ArrayView[4096]))))), ((((-0x8000000)-(0x1eb94703)-(0xffffffff)) & ((((-0x8000000) <= (-0x2fc5b72)))))), ((d0)), ((d0)), ((-1152921504606847000.0)), ((-128.0)), ((-35184372088833.0)), ((-68719476737.0)), ((17.0)), ((-16777217.0)), ((-129.0)), ((137438953471.0)), ((1.5474250491067253e+26)), ((3.022314549036573e+23)), ((-2147483649.0)), ((-16384.0)), ((-0.25)), ((-1.25)), ((-17592186044416.0)), ((-4294967297.0)), ((-1.25)), ((-1.2089258196146292e+24)), ((-4097.0)), ((-1.1805916207174113e+21)), ((-1073741824.0)), ((72057594037927940.0)))|0)-(!((((0xffffffff)-(0xacfe67f5)) ^ ((0x5755c3fd)+(0xffffffff))))))>>>((0xfd6d793c)-(-0x8000000)+(0xafcf7711))) != ((((0xc1f622cb) <= (((0x4a50d664))>>>((0x130b9aca))))-(((-1.9342813113834067e+25) != (8589934593.0)) ? (!(0xf9206085)) : ((0xbf2bc3ed) ? (0xff23a5e7) : (0xfd75f611)))+(0xc74eceda))>>>((0x7d89fea))))))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ print(b2);return (1 for (x in []))})()}, new ArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=1573; tryItOut("\"use strict\"; a0 = a1.concat(t0);function x(w = (void shapeOf((4277))), x)(4277)var ehmzuj = new ArrayBuffer(4); var ehmzuj_0 = new Int16Array(ehmzuj); ehmzuj_0[0] = -20; undefined;");
/*fuzzSeed-248247344*/count=1574; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i0)+(i1)))|0;\n  }\n  return f; })(this, {ff:  /x/g }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, Math.PI, 0, 1, 0.000000000000001, -0x07fffffff, -0x080000000, -1/0, 2**53-2, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, Number.MAX_VALUE, -0x080000001, 42, -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0x100000001, -(2**53+2), -0, -(2**53-2), -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-248247344*/count=1575; tryItOut("\"use strict\"; \"use asm\"; for(let w of /*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , {x:3}, new RegExp(\"(?=[^]|$+)\", \"gm\"), new String('q'), {x:3},  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"),  \"use strict\" , {x:3}, new String('q'), {x:3},  \"use strict\" , new String('q'), {x:3}, new String('q'),  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3}, {x:3}, new RegExp(\"(?=[^]|$+)\", \"gm\"),  \"use strict\" , {x:3}, {x:3}, new RegExp(\"(?=[^]|$+)\", \"gm\"), new String('q'), {x:3},  \"use strict\" ,  \"use strict\" , {x:3},  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3}, new String('q'), {x:3}, {x:3}, new String('q'), new RegExp(\"(?=[^]|$+)\", \"gm\"), new String('q'), {x:3}, {x:3}, new String('q'),  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3},  \"use strict\" , {x:3},  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3}, new String('q'), {x:3}, {x:3},  \"use strict\" , {x:3}, {x:3}, {x:3},  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), new String('q'),  \"use strict\" , {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3}, new String('q'), new RegExp(\"(?=[^]|$+)\", \"gm\"), new String('q'), new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, new RegExp(\"(?=[^]|$+)\", \"gm\"),  \"use strict\" , new RegExp(\"(?=[^]|$+)\", \"gm\"), new RegExp(\"(?=[^]|$+)\", \"gm\"), new String('q'), new String('q'), new String('q'),  \"use strict\" , new String('q'),  \"use strict\" , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new RegExp(\"(?=[^]|$+)\", \"gm\"),  \"use strict\" , new String('q'), new String('q'), new RegExp(\"(?=[^]|$+)\", \"gm\"), {x:3}]) this.zzz.zzz;");
/*fuzzSeed-248247344*/count=1576; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.fround(mathy0(Math.fround(( + mathy0(( + x), ( + ( ~ (y > 0x080000000)))))), Math.fround((x !== Math.fround((Math.fround(( + (x << (x | 0)))) * (Math.atan((y | 0)) | 0))))))) < Math.abs(Math.max((Math.hypot(((mathy0((x | 0), ((( ! (x >>> 0)) >>> 0) | 0)) | 0) >>> 0), ((mathy0(x, y) || ( ! y)) | 0)) >>> 0), (((Math.max((Math.sign(-0x100000001) >= x), Number.MIN_SAFE_INTEGER) | 0) && ((1.7976931348623157e308 , ( + Math.min(( + x), ( + x)))) | 0)) | 0)))); }); testMathyFunction(mathy1, [-1/0, -0x07fffffff, 0x100000000, -0x0ffffffff, Math.PI, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, -0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 0, -(2**53+2), -0, -0x080000001, 1, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 0.000000000000001, 2**53-2, 1/0, 0/0, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1577; tryItOut("Array.prototype.push.call(a0, t0, g2.h2);");
/*fuzzSeed-248247344*/count=1578; tryItOut("a2.splice(NaN, ({valueOf: function() { t2.set(t0, v0);return 15; }}), m0);");
/*fuzzSeed-248247344*/count=1579; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=1580; tryItOut("/* no regression tests found */");
/*fuzzSeed-248247344*/count=1581; tryItOut("mathy1 = (function(x, y) { return ( + Math.pow((Math.round((Math.sign((((y >>> 0) ? ((( + (x >>> 0)) <= x) >>> 0) : -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)) >>> 0), ( + (( + Math.log2(( + (-0x100000001 && ((( + y) % y) | 0))))) === (Math.hypot(y, ( ~ ( + y))) >>> 0))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001, Number.MAX_VALUE, 1/0, 2**53-2, 2**53+2, -0x0ffffffff, -0x100000001, -(2**53-2), 2**53, 1, -1/0, 0x100000000, 0x080000000, 0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0, -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 0/0, -Number.MAX_VALUE, 42, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0, Math.PI, Number.MIN_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1582; tryItOut("Array.prototype.push.call(a1, o2.g1.g1.h1, h0, g0.i2, e1, g0, s0);\nh2 + '';\n");
/*fuzzSeed-248247344*/count=1583; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan2((((((Math.pow((y >>> 0), ((((Math.imul((1/0 >>> 0), (y >>> 0)) >>> 0) || Math.max((Math.min(( + x), y) >>> 0), y)) | 0) | 0)) | 0) ? ((Math.fround(y) == Math.fround(y)) >>> 0) : Math.fround(( ! ( + y)))) | 0) / (((((((2**53+2 || (y >>> 0)) >>> 0) | 0) != (( + (Math.log10((x >>> 0)) >>> 0)) | 0)) | 0) >>> 1) | 0)) >>> 0), (((( ~ ((x !== (y >>> 0)) | 0)) | 0) ? Math.fround((Math.fround(Math.log(Math.trunc(y))) ** Math.fround(( + Math.pow((x >>> 0), x))))) : Math.fround((Math.asin((Math.fround(Math.atan2(y, Math.fround(x))) >>> 0)) | 0))) ? (( - Math.sin((y ? x : x))) || x) : (Math.asin(Math.atan2(Math.cosh(y), Math.fround(( + Math.fround(Number.MIN_VALUE))))) >>> 0))); }); testMathyFunction(mathy0, [1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 42, -(2**53-2), 2**53-2, -0, -1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, 1/0, Number.MIN_VALUE, 1, -0x080000001, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, 2**53+2, -0x100000000, 0x100000000, -0x080000000, 0x0ffffffff, -Number.MIN_VALUE, 0x080000001, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 0, -0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-248247344*/count=1584; tryItOut("Object.defineProperty(this, \"this.a2\", { configurable: (x % 16 != 11), enumerable: (x % 5 == 4),  get: function() {  return Array.prototype.map.call(a0, (function() { for (var j=0;j<16;++j) { f2(j%2==1); } }), v2); } });");
/*fuzzSeed-248247344*/count=1585; tryItOut("\"use strict\"; v1 = (this.g0.f0 instanceof m1);");
/*fuzzSeed-248247344*/count=1586; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround(( + (Math.fround(Math.cbrt(x)) + Math.atanh((( + Math.min(x, Math.fround(Math.min((Math.hypot(y, y) >>> 0), (x | 0))))) >>> 0))))), Math.fround(( + Math.pow(( + (( - x) | 0)), Math.pow(Math.fround(( + Math.fround(1))), Number.MAX_VALUE)))))); }); ");
/*fuzzSeed-248247344*/count=1587; tryItOut("mathy3 = (function(x, y) { return Math.hypot(-14 ? (uneval(\"\\uEFBC\")) ? new ()((y = [[]])) : x : x, (Math.fround(( ! (Math.atan(Math.atan2(x, x)) | 0))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[a **  , a **  , new Boolean(false), function(){}, false, a **  , function(){}, false, new Boolean(false), new Boolean(false), false, function(){}, function(){}, false, a **  , false, new Boolean(false), new Boolean(false), a **  , function(){}, a **  , new Boolean(false), a **  , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-248247344*/count=1588; tryItOut("mathy5 = (function(x, y) { return Math.round(((Math.atan2(((Math.hypot(x, ( ! Math.exp((((0 >>> 0) << (y >>> 0)) >>> 0)))) >>> 0) >>> 0), ((Math.fround(( + x)) == Math.fround((mathy1((y | 0), (Number.MIN_SAFE_INTEGER | 0)) | 0))) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy5, [-0x07fffffff, -0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0, Number.MAX_SAFE_INTEGER, -0x100000001, -0, Number.MIN_VALUE, 1, 0x080000001, 0x07fffffff, 0x100000001, -0x080000000, 0/0, Math.PI, 1/0, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 42, -1/0, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, -(2**53+2), 2**53+2, 0.000000000000001, Number.MAX_VALUE, -(2**53), -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=1589; tryItOut("v0 = evalcx(\"mathy2 = (function(x, y) { return ((Math.acosh(((Math.max((Math.min((Math.max((x != y), mathy1(x, y)) >>> 0), (( ~ -1/0) >>> 0)) >>> 0), Math.log2(( + mathy0(y, x)))) >>> 0) >>> 0)) >>> 0) << (Math.sinh(( + (Math.tanh(Math.log10(x)) >>> 0))) ? (Math.pow((( + (Math.clz32(x) >>> 0)) | 0), ((Math.min(y, ( + ( + Math.max(( + y), (mathy1(Math.fround(x), x) | 0))))) | 0) | 0)) | 0) : ( + (( - Math.log10(x)) + (Math.pow(Math.ceil(1/0), (y > ( + y))) >> (y | 0)))))); }); testMathyFunction(mathy2, /*MARR*/[new Boolean(true),  '\\\\0' ,  '\\\\0' , true,  '\\\\0' ,  '\\\\0' ,  '\\\\0' , new Boolean(true), true, true,  '\\\\0' ,  '\\\\0' ,  '\\\\0' ,  '\\\\0' , new Boolean(true),  '\\\\0' , new Boolean(true), true, true, true, true, true, new Boolean(true),  '\\\\0' ,  '\\\\0' , true, new Boolean(true), true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, true, new Boolean(true), true,  '\\\\0' ,  '\\\\0' ,  '\\\\0' , new Boolean(true), new Boolean(true),  '\\\\0' , true, true,  '\\\\0' , true, true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  '\\\\0' , new Boolean(true),  '\\\\0' , true]); \", g1);");
/*fuzzSeed-248247344*/count=1590; tryItOut("\"use strict\"; t2[(4277)] = f1;");
/*fuzzSeed-248247344*/count=1591; tryItOut("\"use asm\"; testMathyFunction(mathy1, [-(2**53+2), 0x080000001, 2**53, Number.MAX_VALUE, -0, Number.MIN_VALUE, -0x100000000, -(2**53-2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, -(2**53), 2**53-2, 0/0, 1, -0x100000001, 2**53+2, 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, 0x100000001, -Number.MIN_VALUE, -0x080000000, -1/0, 0x100000000]); ");
/*fuzzSeed-248247344*/count=1592; tryItOut("mathy4 = (function(x, y) { return (Math.pow(Math.log1p(((( ! (mathy1((x | 0), (x | 0)) | 0)) | 0) | 0)), ((x > Math.fround(y)) | 0)) !== ((( + ( - mathy2((( ! Math.min(-Number.MAX_SAFE_INTEGER, y)) / (x > Math.hypot(y, Number.MAX_SAFE_INTEGER))), ((Math.fround(Math.log2((x >>> 0))) | 0) ** ( + y))))) ? (( + (Math.cbrt(( + y)) | 0)) ? Math.fround(( - x)) : Math.fround((x <= Math.fround((0x100000001 != mathy2(2**53+2, 2**53)))))) : Math.log2((x | 0))) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[function(){}, .2, new Boolean(false), function(){}, function(){}, .2, .2, new Boolean(false), .2,  '' , function(){}, .2, new Boolean(false),  '' , function(){}, new Boolean(false), function(){}, new Boolean(false), function(){}, .2, function(){}, function(){}, function(){}, function(){}, .2,  '' , new Boolean(false), function(){}, new Boolean(false), function(){}, .2, new Boolean(false),  '' , function(){}, .2, function(){}, function(){}, .2, .2, .2, function(){}, .2, new Boolean(false), new Boolean(false),  '' ]); ");
/*fuzzSeed-248247344*/count=1593; tryItOut("{ void 0; void gc('compartment'); }yield /*UUV2*/(y.keys = y.propertyIsEnumerable);");
/*fuzzSeed-248247344*/count=1594; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((( + (( + Math.max(Math.max((( + (-0x07fffffff | 0)) | 0), Math.max(( + 2**53+2), ( + y))), Math.imul(( + Math.atan2(y, x)), (( ~ x) >> y)))) % ( + (( ~ ((Math.imul((((( ! x) ^ -0x100000000) | 0) >>> 0), y) | 0) >>> 0)) >>> 0)))) >>> 0) >>> (Math.pow(Math.min((2**53 == Math.pow(( + (Math.log2(((mathy1((0x080000000 | 0), -Number.MAX_VALUE) | 0) >>> 0)) >>> 0)), ( + 1/0))), Math.clz32(Math.asin(Math.fround(Math.fround(Math.min(y, Math.atan2(y, ( + x)))))))), Math.tan(0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 0, 1, 0x100000000, -Number.MAX_VALUE, 2**53+2, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, Math.PI, 1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 42, 2**53-2, Number.MIN_VALUE, 0/0, -1/0, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), -0x0ffffffff, -0x100000001, 2**53, -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-248247344*/count=1595; tryItOut("/*RXUB*/var r = r1; var s = s0; print(s.match(r)); ");
/*fuzzSeed-248247344*/count=1596; tryItOut("/*RXUB*/var r = /(?:((?:\\w{3,3}\\b\\b{0,}))+?)|(?=((?!$))$|.\\d*?)?*?(?:(\u00cd){0})|\\B|(?=[^\\w\\S\\S\\u00F8-\\\u5526])/g; var s = \" \\u00cc\\n a11aa \\u859a1 \\u00c4\\na\\u9175 b\\u009a\\na\\nb\\u009a\\na\\nb\\u009a\\na\\n1b\\u009a\\na\\nb\\u009a\\na\\nb\\u009a\\na\\nb\\u009a\\na\\nb\\u009a\\na\\n\"; print(s.search(r)); ");
/*fuzzSeed-248247344*/count=1597; tryItOut("\"use strict\"; h1.getOwnPropertyDescriptor = f0;");
/*fuzzSeed-248247344*/count=1598; tryItOut("this.t0.set(a1, 15);");
/*fuzzSeed-248247344*/count=1599; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + ( + Math.hypot(( + ((Math.min((Math.PI | 0), ( + Math.pow(( ! y), ( + (y | y))))) | 0) <= (((Math.fround((y && x)) | (Math.abs(y) >>> 0)) >>> 0) | 0))), Math.log(y)))) || ( + mathy2(( + ( ~ x)), ( + (( + x) >>> ( + (Math.hypot(((x / Number.MAX_VALUE) >>> 0), (( + Math.log1p(((( ~ (x | 0)) | 0) >>> 0))) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy4, ['/0/', ({valueOf:function(){return '0';}}), null, 0, (new String('')), (new Boolean(true)), true, false, (new Number(0)), '0', (new Number(-0)), -0, ({valueOf:function(){return 0;}}), /0/, '', 0.1, ({toString:function(){return '0';}}), (function(){return 0;}), 1, objectEmulatingUndefined(), (new Boolean(false)), NaN, '\\0', undefined, [], [0]]); ");
/*fuzzSeed-248247344*/count=1600; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( - Math.fround((Math.fround(((Math.trunc(( - y)) ? (( + (((Math.pow(y, (y | 0)) | 0) * y) >>> 0)) >>> 0) : -Number.MIN_VALUE) ^ x)) ? Math.fround(( - ((( + (Math.atan2(x, y) >>> 0)) >>> 0) | 0))) : Math.expm1(( + Math.min(( + (( + (x == -0x0ffffffff)) >>> y)), (Math.tan(x) >>> 0)))))))); }); testMathyFunction(mathy0, [-0, objectEmulatingUndefined(), [], undefined, [0], (new Boolean(false)), 0, ({valueOf:function(){return 0;}}), (new Boolean(true)), (new Number(0)), (function(){return 0;}), (new String('')), '\\0', null, (new Number(-0)), false, 1, /0/, true, ({toString:function(){return '0';}}), '0', '', ({valueOf:function(){return '0';}}), 0.1, '/0/', NaN]); ");
/*fuzzSeed-248247344*/count=1601; tryItOut("g0 + '';");
/*fuzzSeed-248247344*/count=1602; tryItOut("let x = this.__defineGetter__(\"e\", (function(x, y) { return ( + (( + (y && ( + x))) - x)); })), eval = x = x, dflnke, e = (( - ( + (( + (x ^ x)) ^ ( + Math.trunc(x))))) <= -1/0), x = , c = (\"\\u5B42\".yoyo( /x/ )), w = /\\1/im, vdqemz; for (let d of ((4277)\n)) v2 = (i2 instanceof a1);");
/*fuzzSeed-248247344*/count=1603; tryItOut("h2.get = f1;");
/*fuzzSeed-248247344*/count=1604; tryItOut("g1.a2[15] = 28;");
/*fuzzSeed-248247344*/count=1605; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( + ( + Math.max((Math.acos(Math.min(mathy1(( + mathy1(( + Math.fround(Math.atan2(Math.fround(x), Math.fround(y)))), (x >>> 0))), 1), (Math.atan2(y, 1) | 0))) | 0), ( + (x ? ( + y) : ( + Math.acos(Math.max(( + y), ( + Math.imul(1/0, y)))))))))))); }); ");
/*fuzzSeed-248247344*/count=1606; tryItOut("undefined\n;");
/*fuzzSeed-248247344*/count=1607; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! Math.fround(Math.acos(Math.fround(Math.hypot(( ! x), ( + Math.cos(Math.PI))))))); }); testMathyFunction(mathy4, [0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, Math.PI, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, -0x100000001, Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, -0x080000000, -0, 2**53+2, -0x100000000, -Number.MIN_VALUE, 0/0, 0, 42, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -0x080000001, 1, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, -(2**53-2), 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-248247344*/count=1608; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-248247344*/count=1609; tryItOut("var lkebuw = new SharedArrayBuffer(8); var lkebuw_0 = new Int32Array(lkebuw); print(lkebuw_0[0]); lkebuw_0[0] = 22; var lkebuw_1 = new Int16Array(lkebuw); this.b2.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 65.0;\n    (Int8ArrayView[1]) = (((0x88657a13))+((0x8b6ae8c9) ? (0x17f8f0ee) : ((4277))));\n    i0 = ((((imul((i0), (0xf8c2c8f3))|0) % ((( /x/g ) % (((0xf004b6e4))>>>((-0x8000000)))) ^ (((0xa307f7dd)))))>>>((0x29459e7))));\n    i0 = ((((-0x8000000)-((d2) >= (Infinity)))>>>(((((!(-0x8000000))*0xfffff) | (((0xf9cacf0e) ? (0x7d8bc397) : (0x1c822ef7)))) != ((((0x0) != (0xd6af01f5))*-0x4569e) ^ ((0xf8637b67)*0xe52a8)))+(0xc888bf64))));\n    return +((1.0));\n    (Int16ArrayView[(((((0xbc692008))>>>(((0xe168643c) <= (0xbd9937ce))-((((0xffd5a028))>>>((0xf96497c6)))))))) >> 1]) = ((0xfba9f993)+(0xffd20dbe)-(0x4ea17f6c));\n    d2 = ((0x6de7fda2) ? (((2199023255553.0) <= (-16777217.0)) ? (-4.722366482869645e+21) : (((Float64ArrayView[0])) / ((((-1.125)) * ((257.0)))))) : (-3.094850098213451e+26));\n    d2 = (d2);\n    (Float32ArrayView[((i0)*0x4c9b) >> 2]) = ((d1));\n    (Uint16ArrayView[0]) = ((!(((((0xfe4aa6a8))>>>((-0x4043b6f))) < (0xb30f0520)) ? (i0) : ((4294967297.0) < ((-16777216.0) + (-511.0)))))+(i0)+(0xff8c18fa));\n    d1 = (-1048575.0);\n    d1 = (d1);\na2.reverse();    i0 = (!((0x1fc652c4)));\n    return +((+abs((((void options('strict')))))));\n  }\n  return f; });o2.v1 = new Number(i1);a2.unshift(p2, f0);/* no regression tests found */let (lkebuw_1, x = lkebuw_0[0], e, lkebuw = (({\"-1\": false,  set \"12\"(b, ...y) { \"use strict\"; yield window }  }).unwatch(window)), eval, z = (Math.imul( '' ,  /x/ )), kqpkmx, this, oibmbt, lkebuw_0[0]) { for (var p in v1) { try { v2 = evalcx(\"mathy1 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var ff = foreign.ff;\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var d3 = 2147483647.0;\\n    var d4 = -4.835703278458517e+24;\\n    var i5 = 0;\\n    var i6 = 0;\\n    {\\n      d1 = (((d4)) % (Math.max(10, 7)));\\n    }\\n    return +(((Infinity) + (x)));\\n    return +((Int32ArrayView[((i0)) >> 2]));\\n  }\\n  return f; })(this, {ff: Math.acos}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, -0x0ffffffff, -0x080000001, 1/0, 0x080000001, -0x100000000, 0x080000000, 2**53+2, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 0x100000001, 0x07fffffff, 0, -(2**53-2), -0, 0x100000000, 0/0, -(2**53), 0.000000000000001, -0x07fffffff, 2**53-2, 42, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 1]); \", g0); } catch(e0) { } try { delete o1[\"toLocaleDateString\"]; } catch(e1) { } try { g0.e2.has(((yield  /x/ ))); } catch(e2) { } a1.unshift(t1, o2.h1, p0); } }");
/*fuzzSeed-248247344*/count=1610; tryItOut("");
/*fuzzSeed-248247344*/count=1611; tryItOut("g2.t1[3] = y(x, window).yoyo(/*FARR*/[(x ? (b = Proxy.createFunction(({/*TOODEEP*/})(null), \"\\uF32E\")) : (void version(180))), ...([1] for each (\u000cx in ({})) if (c)), false, .../*FARR*/[(new this( /x/g )), (4277), .../*PTHR*/(function() { for (var i of []) { yield i; } })(), , [,,z1], .../*FARR*/[...[],  /x/ , \"\\uC3A0\", ,  /x/ ], .../*FARR*/[x], Math.atan(20), (makeFinalizeObserver('nursery')), x, x, ((yield  /x/g \u000c)), ...[ /x/g .watch(\"arguments\", (function(x, y) { \"use strict\"; return y; })) if (\"\\uC8CD\")], ...[let (c)  \"\" \u000c for (x of  \"\" ) for each (y in ({a1:1}))], \u3056 = [], (4277), , x, + '' , , ...[e ? -10 : 18], Math.atan2(-9, \"\\u1BD2\"), , , ...runOffThreadScript, (makeFinalizeObserver('nursery')), .../*FARR*/[({a2:z2}), this, {}, new RegExp(\"((?:.\\\\u00e6\\\\b){2,33554434})\", \"gym\"), this, d], (new (undefined)(undefined)), ...new Array(0.102)]].map);");
/*fuzzSeed-248247344*/count=1612; tryItOut("testMathyFunction(mathy2, [-0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 0, -0x080000000, 0x07fffffff, 0x080000001, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), 0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -0, 2**53+2, 0/0, -Number.MIN_VALUE, 42, 0.000000000000001, -(2**53-2), -0x100000001, -0x0ffffffff, 0x080000000, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, -(2**53), Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-248247344*/count=1613; tryItOut("\"use strict\"; x.lineNumber;throw StopIteration;");
/*fuzzSeed-248247344*/count=1614; tryItOut("var xnqemf, x, \"2\", x =  \"\" , y;/*RXUB*/var r = new RegExp(\".\", \"y\"); var s = \"\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1615; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1616; tryItOut("\"use strict\"; const x = (x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { throw 3; }, }; })( /x/g ), Function, Map.prototype.values)), {y, y: tan} = let (w = \"\\u32FB\") [,](new RegExp(\"(?!\\\\1)\", \"yi\"), timeout(1800)), y, diggkl;o2.o0.m0 + a2;");
/*fuzzSeed-248247344*/count=1617; tryItOut("a1 = new Array;\no2.v2 = Object.prototype.isPrototypeOf.call(p0, g2.e2);\n");
/*fuzzSeed-248247344*/count=1618; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.min(Math.fround(Math.round(Math.fround(mathy0(( + Math.trunc(( + y))), 0/0)))), Math.fround(Math.pow((mathy1(y, (Math.asin(1/0) / ( ~ x))) >>> 0), Math.max(-0, (mathy1(x, mathy2(x, x)) >>> 0))))) ? ( ! Math.hypot(Math.cosh(Math.trunc(-1/0)), Math.imul((x | 0), (( + (Math.imul(y, (mathy0(x, (1 | 0)) | 0)) >> (0 >= x))) | 0)))) : ( ! ( + Math.fround(Math.atan(Math.fround(x)))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, -1/0, 1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53-2, 0, Number.MIN_VALUE, 0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 0x100000000, 0x080000001, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, Number.MAX_VALUE, 2**53+2, 42, -0x100000000, 1, -(2**53-2), 2**53, Math.PI, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1619; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! (( - (( - (Math.log10(( + (((y >>> 0) ** (y >>> 0)) | 0))) >>> 0)) | 0)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[[], [], (makeFinalizeObserver('tenured')), {}, []]); ");
/*fuzzSeed-248247344*/count=1620; tryItOut("\"use strict\"; var c = true;o1.m2 = new Map(g2);function x(NaN = -11, a = 26)(4277)z = linkedList(z, 3600);\nwith((4277)){\"\\u75D0\";print(x); }\n");
/*fuzzSeed-248247344*/count=1621; tryItOut("\"use strict\"; \"use asm\"; v1 = r1.source;");
/*fuzzSeed-248247344*/count=1622; tryItOut("\"use strict\"; a1.push(t2, t2, a0, g0);");
/*fuzzSeed-248247344*/count=1623; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.tanh(Math.fround(( + (( + ( ~ Math.sign(-0))) >= ( + ((( - Math.log10(Math.atan2(y, Math.fround(y)))) < (Math.expm1((( ! ( + Math.sin(0))) >>> 0)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy4, [0.000000000000001, 1/0, 0/0, -(2**53-2), 0x100000000, Number.MIN_SAFE_INTEGER, 42, -0, -0x080000001, 2**53, 0, -0x07fffffff, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, 0x100000001, 0x080000000, 1, 1.7976931348623157e308, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 2**53-2, 2**53+2, Math.PI, Number.MIN_VALUE, -0x100000001, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1624; tryItOut("s0 += 'x';d = (new  '' ());\nthis.a2[10] =  '' ;\n");
/*fuzzSeed-248247344*/count=1625; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^\\\\u0065\\\\S\\\\\\u0098]{0,0}\", \"im\"); var s = \"0\"; print(r.test(s)); ");
/*fuzzSeed-248247344*/count=1626; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[(0/0), x]) { /* no regression tests found */ }");
/*fuzzSeed-248247344*/count=1627; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( ~ Math.fround((Math.imul(mathy0(((x | 0) | Math.fround((-(2**53) + Math.atanh(y)))), (mathy0((1.7976931348623157e308 >>> 0), (Number.MIN_VALUE >>> 0)) >>> 0)), y) > ( + Math.atan2(( + Math.pow((((Math.min((y | 0), (x | 0)) | 0) != y) / (x >>> 0)), ( + Math.log1p(x)))), ( + x))))))); }); testMathyFunction(mathy3, [0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -1/0, 42, -(2**53), 0.000000000000001, -0, -0x080000000, -(2**53-2), 0x07fffffff, 0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, -0x080000001, Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, 2**53+2, Math.PI, 1.7976931348623157e308, -(2**53+2), 2**53-2, -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, 1, 0x100000000, -0x100000001, -0x07fffffff]); ");
/*fuzzSeed-248247344*/count=1628; tryItOut("a2 = t1[16];");
/*fuzzSeed-248247344*/count=1629; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - ((((Math.fround(Math.sin(( ~ ( + mathy1(( + x), ( + y)))))) >>> 0) ? (x >>> 0) : ((mathy1(y, ( + y)) >>> ( + ((-0x100000001 >>> 0) ? (y >>> 0) : (-(2**53-2) >>> 0)))) >>> 0)) >>> 0) === ((( - (mathy1((1.7976931348623157e308 >>> 0), ( + x)) | 0)) | 0) | mathy0(Math.log(Math.min(0x100000001, 0x100000001)), (Math.fround(Math.exp(x)) , Math.fround(( ! Math.fround(x)))))))); }); testMathyFunction(mathy2, [[], false, ({toString:function(){return '0';}}), true, -0, 0, (new Boolean(true)), '/0/', (function(){return 0;}), (new Number(0)), null, 1, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '\\0', undefined, /0/, ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(false)), '', NaN, '0', 0.1, [0], (new Number(-0))]); ");
/*fuzzSeed-248247344*/count=1630; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /(?=\\B)|(?=\\S|.{1,})|[\\r\\D\\v-\\\u6f83]*?(?:[\\D]\\3{2,5})((?!.))*(?!(?!(?!\\B))|(?:[^]{3})*)\\2\\d{4}(?:\ub14a|$\\s|\\D)|[^]*|(?!((?:.\\B*|(?:[\u00f1-\\u1215\u5f14@-\\xa4\\s])+)))*?/gy; var s = \"\"; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-248247344*/count=1631; tryItOut("m2.has(p1);");
/*fuzzSeed-248247344*/count=1632; tryItOut("/*bLoop*/for (var nevzbh = 0; nevzbh < 9; ++nevzbh) { if (nevzbh % 9 == 5) { print(x); } else { s1 = ''; }  } ");
/*fuzzSeed-248247344*/count=1633; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.round(Math.fround((Math.hypot((Math.atan2(((((( ! x) >>> 0) ? y : ((y | 0) | 2**53+2)) >>> 0) != (( ~ x) | 0)), ( + (( + Math.hypot(x, x)) , mathy0(x, y)))) | 0), ((mathy0(Number.MAX_SAFE_INTEGER, (Math.trunc((Number.MIN_SAFE_INTEGER >= Math.imul(x, y))) | 0)) >>> 0) | 0)) && (mathy1(-0x080000001, (x >>> 0)) << Math.fround((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14) { var r0 = a9 & 5; a4 = a6 & a12; var r1 = 2 + a12; a2 = 1 % a11; print(a3); var r2 = x / 8; var r3 = a14 * a11; var r4 = a10 | a13; var r5 = a2 | 9; var r6 = 0 + a11; var r7 = 4 - a4; a4 = a13 | r2; var r8 = a1 + a13; var r9 = a11 ^ a6; a7 = a6 - x; var r10 = 2 * r0; var r11 = 7 % 3; var r12 = 4 % 8; var r13 = r5 % a13; var r14 = a7 + a1; var r15 = 4 | r8; print(a1); var r16 = r6 - r11; var r17 = 2 & r13; a8 = 7 / r9; a7 = 5 - r6; var r18 = 8 ^ y; var r19 = 9 ^ r1; var r20 = a7 * r14; var r21 = a11 * r7; var r22 = r15 + 9; var r23 = r0 % r5; a1 = r3 + 5; var r24 = 2 % r10; var r25 = 3 * a1; r16 = a7 ^ x; r13 = a3 & 5; var r26 = a14 % 4; a7 = a14 % r14; var r27 = a13 | x; var r28 = 1 - r10; var r29 = 5 + r18; var r30 = 1 - a14; var r31 = 6 - a14; var r32 = 5 + r25; var r33 = r14 / r26; var r34 = r18 + a13; var r35 = 3 + 2; var r36 = r34 | r16; var r37 = r25 | 3; r8 = 6 | a8; var r38 = a13 ^ r4; var r39 = r5 * r38; print(r25); var r40 = r33 + 6; r8 = r19 | r39; var r41 = r20 | a4; var r42 = r38 + a0; print(r19); r40 = r27 ^ r18; var r43 = r26 ^ 3; x = r17 + r14; var r44 = r19 / r30; var r45 = r3 | a10; var r46 = 1 & a2; var r47 = 4 - a5; var r48 = r2 | r7; r2 = r42 / r45; var r49 = r2 ^ 1; var r50 = 4 % r14; var r51 = r0 + r22; var r52 = r6 & 5; var r53 = r35 - x; var r54 = 8 & r40; print(r17); var r55 = 3 & 2; var r56 = 6 + r37; a3 = 6 ^ r17; var r57 = r45 + 2; var r58 = r17 - r14; r14 = 5 ^ 9; print(r33); var r59 = 7 % 0; r49 = a12 + x; var r60 = a6 * r54; a8 = a11 % r34; var r61 = 8 / r34; var r62 = r37 + 7; var r63 = 1 ^ 4; var r64 = 2 - a8; x = r56 % 4; a10 = 9 % r18; var r65 = r26 & 2; var r66 = r0 & r25; var r67 = r2 % a6; var r68 = r3 | r56; var r69 = a11 % r46; var r70 = r39 | 5; var r71 = r46 / 7; var r72 = 7 * 1; var r73 = y % a3; var r74 = r6 / r58; var r75 = 1 & r0; var r76 = r68 + r14; var r77 = 1 + 4; var r78 = r51 * 9; var r79 = 5 - r23; var r80 = r28 ^ 9; var r81 = a1 | r23; a0 = r61 % a7; var r82 = r39 + r61; var r83 = r4 + a11; r54 = r37 + r40; r33 = 4 % r57; var r84 = r18 + r15; var r85 = r42 ^ 1; print(a5); var r86 = r3 + 8; var r87 = 8 | r37; var r88 = 3 % r53; var r89 = 8 / 0; r36 = r38 + a11; var r90 = r7 - r52; var r91 = r26 | a14; r75 = r58 * r88; var r92 = r21 & 3; var r93 = r75 % r38; var r94 = a10 + r22; var r95 = r37 / r81; var r96 = r29 / r83; var r97 = r50 * r49; var r98 = r51 * r54; var r99 = r95 + r5; var r100 = r60 / r3; var r101 = r0 | r90; var r102 = r99 - r21; var r103 = 0 / r61; var r104 = r102 / r93; r78 = r95 * r81; r92 = r45 + r71; var r105 = 1 % 4; var r106 = a1 % 7; var r107 = 9 % r92; var r108 = 6 % a3; var r109 = r84 / 1; var r110 = 9 / 9; var r111 = 8 + r103; var r112 = r3 ^ r79; var r113 = 7 - 0; var r114 = r57 / r59; var r115 = r4 / 8; var r116 = 2 / 8; var r117 = r35 | r54; r82 = 2 / 2; r82 = 7 + 6; var r118 = r67 - r106; var r119 = r105 / 9; var r120 = r64 * r50; var r121 = r5 & r112; r18 = r79 | r93; r103 = r76 / r121; print(r31); var r122 = r50 ^ 7; var r123 = r3 | r41; r102 = r93 + r112; var r124 = 7 * r81; var r125 = r63 | r41; a4 = 4 % r95; var r126 = a9 | r9; var r127 = 2 + r0; r3 = 0 / r91; var r128 = y % r90; print(r14); var r129 = 0 / r104; var r130 = r65 * r69; var r131 = 2 & 0; r35 = r62 % 0; var r132 = r126 | r74; r63 = a4 / r14; var r133 = 7 | r5; print(r43); var r134 = r55 + r31; var r135 = r4 / a5; var r136 = 8 & r54; var r137 = a8 - r70; r63 = a9 & 5; a12 = r39 - r19; var r138 = r5 + r27; var r139 = r73 + 5; var r140 = 3 * 9; var r141 = r139 * r100; var r142 = r80 * a4; var r143 = r112 & r18; var r144 = r0 - r35; var r145 = 9 & r144; var r146 = 8 * 8; print(r30); var r147 = 7 * r6; r95 = r25 + r63; var r148 = r137 & r75; r70 = 1 * r81; var r149 = 1 / r109; var r150 = r1 & r100; var r151 = r4 ^ 7; var r152 = r18 | r82; var r153 = r101 & r128; var r154 = r108 % 5; var r155 = 7 ^ x; r134 = 4 * r145; r19 = r95 & r110; var r156 = r30 + r75; r145 = r47 % y; var r157 = r73 / r136; var r158 = 8 ^ r60; var r159 = r68 % a10; var r160 = r121 * r127; r13 = 6 ^ 7; print(r49); a1 = r73 / 2; r89 = r151 & r68; r16 = r69 + r87; r0 = r154 % r142; var r161 = r111 | r85; r60 = r133 ^ r115; var r162 = r3 | r99; var r163 = 6 + 1; r39 = 4 ^ 5; r34 = r133 / 1; print(r92); r100 = r149 | 5; var r164 = 1 + r63; var r165 = r129 + 7; print(r39); var r166 = 6 - r123; var r167 = 6 + r68; var r168 = r61 * 2; var r169 = 1 % r139; r132 = 9 * 4; r74 = r165 | 9; var r170 = r39 & r4; var r171 = r91 & r144; r56 = 8 + r77; r22 = r102 - r22; var r172 = r95 / 2; var r173 = 4 ^ r155; var r174 = r118 | r69; var r175 = r160 - r10; var r176 = r139 + r128; var r177 = r104 & 5; var r178 = r97 / r12; var r179 = r166 - r25; var r180 = r36 & 7; var r181 = 9 | 3; var r182 = 4 - r176; print(r62); r161 = r131 / r97; var r183 = r8 + r91; r157 = 8 * r134; var r184 = a1 - a1; var r185 = r34 ^ 9; var r186 = x / r19; var r187 = 8 ^ r178; var r188 = r83 & 8; var r189 = 8 - r132; var r190 = 4 / r83; var r191 = 4 - 6; var r192 = r85 & 6; var r193 = 5 & r103; r144 = x ^ a4; print(r159); var r194 = r161 | r120; r108 = 5 | r134; var r195 = 4 & 2; var r196 = r188 - r27; r55 = 7 | r23; print(r130); var r197 = r143 | r191; var r198 = r112 + 2; y = r9 ^ r195; var r199 = r193 - r65; var r200 = 3 | a1; var r201 = 4 - 4; var r202 = r13 ^ r157; var r203 = r129 + r55; var r204 = 2 & 4; var r205 = 8 * a2; r11 = 5 / r183; var r206 = 0 * 1; var r207 = r4 % 3; var r208 = 9 & r126; var r209 = a2 | 4; r52 = r191 ^ 8; var r210 = r159 + r118; r22 = 4 | r134; r136 = r96 - r71; r135 = 1 * r63; r170 = r88 + 9; var r211 = 1 / r154; r70 = 7 * r159; r10 = r46 ^ r43; var r212 = r5 / r128; return a0; }))))))); }); testMathyFunction(mathy5, [0.000000000000001, Math.PI, Number.MAX_VALUE, -0x100000000, 1/0, -(2**53+2), -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 0, 0x100000000, 2**53+2, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, -0x080000000, 0/0, 0x100000001, 42, -0, -(2**53-2), 1, 0x080000000, 0x0ffffffff, -0x07fffffff, -1/0, -(2**53), 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=1634; tryItOut("h0.getOwnPropertyDescriptor = (function(j) { f0(j); });");
/*fuzzSeed-248247344*/count=1635; tryItOut("testMathyFunction(mathy4, [0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, -0, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 0, 0x0ffffffff, 2**53+2, 0/0, -(2**53-2), 0x100000001, -(2**53), -0x080000000, 1, -0x100000001, 0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Math.PI, 42, Number.MAX_SAFE_INTEGER, 2**53, -1/0, 2**53-2, -0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-248247344*/count=1636; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[2]) = ((((+(-1.0/0.0))) * ((d0))));\n    d1 = (d0);\n    (Float32ArrayView[2]) = ((NaN));\n    {\n      {\n        d0 = ((0xffe09107) ? (d0) : (d0));\n      }\n    }\n    {\n      {\n        {\n          {\n            {\n              d1 = (((!(((((0x5088aa03) != (0x682f4d37)))>>>((0xb0877906))))) ? (d1) : (d1)) + (d1));\n            }\n          }\n        }\n      }\n    }\n    return +((((d0)) % ((d0))));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-248247344*/count=1637; tryItOut("\"use strict\"; ");
/*fuzzSeed-248247344*/count=1638; tryItOut("\"use strict\"; ((x > x));");
/*fuzzSeed-248247344*/count=1639; tryItOut("\"use strict\"; print(x);yield new RegExp(\"\\\\3\", \"gi\");");
/*fuzzSeed-248247344*/count=1640; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-248247344*/count=1641; tryItOut("v2 = Array.prototype.reduce, reduceRight.call(g1.a1, (function(j) { if (j) { try { i1.next(); } catch(e0) { } try { s2 += 'x'; } catch(e1) { } try { this.v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 94 == 50) })); } catch(e2) { } g2.o0.s2 += 'x'; } else { try { v1 = (a0 instanceof m0); } catch(e0) { } Array.prototype.splice.apply(a2, [NaN, 1]); } }), f0, f1, i0);");
/*fuzzSeed-248247344*/count=1642; tryItOut("\"use strict\"; v2 = Array.prototype.some.apply(a1, [(function() { for (var j=0;j<5;++j) { f1(j%4==0); } }), m2, a0, this.o2.i0, b1]);");
/*fuzzSeed-248247344*/count=1643; tryItOut("this.a2.sort((function mcc_() { var fowrxa = 0; return function() { ++fowrxa; this.f0(/*ICCD*/fowrxa % 10 == 1);};})());");
/*fuzzSeed-248247344*/count=1644; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), -0x100000001, 0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, 0/0, 0x07fffffff, 42, Math.PI, 2**53-2, 0x100000000, -0x07fffffff, 1, -(2**53+2), 1.7976931348623157e308, Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 2**53+2, -1/0, 0x080000000]); ");
/*fuzzSeed-248247344*/count=1645; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(Math.min(Math.fround((Math.min((Math.max(( + x), (Math.imul((( - y) >>> 0), Math.hypot(Math.sin(x), 0x100000001)) >>> 0)) >>> 0), ((Math.hypot(((Math.fround(Math.hypot(y, Math.fround(( + y)))) ? Math.acosh(x) : -Number.MAX_SAFE_INTEGER) | 0), (( ~ (( + Math.min(( + Math.round(y)), ( + x))) | 0)) | 0)) | 0) >>> 0)) >>> 0)), (Math.sinh(Math.pow(x, (( ! (y | 0)) | 0))) >>> 0))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -(2**53+2), 0/0, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, 0x100000001, 0x100000000, -0x07fffffff, Number.MIN_VALUE, -0x080000001, -0x100000000, 42, 0, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, 0x080000001, 2**53-2, 2**53+2, 1/0, 0x07fffffff, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, -(2**53), 2**53, -1/0, -0, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-248247344*/count=1646; tryItOut("const d = (delete \u3056.w);for (var v of o1.g1.b0) { try { a0 = []; } catch(e0) { } v2 = t0.length; }");
/*fuzzSeed-248247344*/count=1647; tryItOut("mathy0 = (function(x, y) { return Math.pow(( ! ((Math.ceil((x | 0)) >>> 0) >= 1.7976931348623157e308)), ( ! ( + ((Math.log2(Math.fround(x)) | 0) & ( + ( ~ Math.pow(0/0, (((x | 0) > (y | 0)) | 0)))))))); }); testMathyFunction(mathy0, [2**53, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 2**53-2, 0.000000000000001, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, 1/0, 2**53+2, -0, -Number.MAX_SAFE_INTEGER, -1/0, 0x080000000, 0, 0x07fffffff, -0x080000000, 0x100000001, -(2**53-2), -Number.MIN_VALUE, -0x07fffffff, -(2**53), 42, -0x080000001, 1, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 0x0ffffffff, -(2**53+2), 1.7976931348623157e308]); ");
/*fuzzSeed-248247344*/count=1648; tryItOut("mathy1 = (function(x, y) { return y; }); testMathyFunction(mathy1, [-(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 1, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -0x100000000, -0x07fffffff, -0x080000001, 2**53+2, 0/0, 2**53, -0, Number.MIN_VALUE, 2**53-2, 1/0, -0x0ffffffff, 0, 0x100000001, 42, Math.PI, 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), -0x080000000, -0x100000001, 0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-248247344*/count=1649; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:[^]?){262145,262147}[^]\", \"gyi\"); var s = \"\\n\"; print(s.match(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
