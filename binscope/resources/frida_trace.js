// frida_trace.js — binscope dynamic tracer.
//
// Hooks a set of network / file / process / crypto / dynamic-loading exports
// across platforms and prints one JSON object per call to the console, which
// the Frida stage captures with `-o frida.log` and parses.
//
// Each line: {"cat": "...", "api": "...", "arg": "...", "ts": <ms>}
//
// This only observes; it does not modify behaviour. It runs inside the target
// process, so only run it on a disposable, network-contained machine.

'use strict';

function emit(cat, api, arg) {
  try {
    console.log(JSON.stringify({
      cat: cat,
      api: api,
      arg: (arg === undefined || arg === null) ? '' : String(arg).slice(0, 200),
      ts: Date.now()
    }));
  } catch (e) { /* ignore */ }
}

function readCStr(p) {
  try { return p.isNull() ? '' : Memory.readUtf8String(p); } catch (e) { return ''; }
}
function readWStr(p) {
  try { return p.isNull() ? '' : Memory.readUtf16String(p); } catch (e) { return ''; }
}

// export name -> [category, argFormatter]. argFormatter(args) -> string.
var HOOKS = {
  // --- dynamic loading (resolve-what-else-gets-hooked) ---
  'dlopen':          ['loader',  function (a) { return readCStr(a[0]); }],
  'dlsym':           ['loader',  function (a) { return readCStr(a[1]); }],
  'LoadLibraryA':    ['loader',  function (a) { return readCStr(a[0]); }],
  'LoadLibraryW':    ['loader',  function (a) { return readWStr(a[0]); }],
  'LoadLibraryExW':  ['loader',  function (a) { return readWStr(a[0]); }],
  'GetProcAddress':  ['loader',  function (a) { return readCStr(a[1]); }],

  // --- file ---
  'open':            ['file',    function (a) { return readCStr(a[0]); }],
  'fopen':           ['file',    function (a) { return readCStr(a[0]); }],
  'CreateFileW':     ['file',    function (a) { return readWStr(a[0]); }],
  'CreateFileA':     ['file',    function (a) { return readCStr(a[0]); }],
  'DeleteFileW':     ['file',    function (a) { return readWStr(a[0]); }],
  'unlink':          ['file',    function (a) { return readCStr(a[0]); }],

  // --- network ---
  'connect':         ['network', function (a) { return 'fd=' + a[0]; }],
  'getaddrinfo':     ['network', function (a) { return readCStr(a[0]); }],
  'send':            ['network', function (a) { return 'len=' + a[2]; }],
  'WSAStartup':      ['network', function (a) { return 'winsock'; }],
  'InternetOpenUrlW':['network', function (a) { return readWStr(a[1]); }],
  'HttpSendRequestW':['network', function (a) { return 'http'; }],
  'URLDownloadToFileW':['network',function (a){ return readWStr(a[2]); }],

  // --- process / exec ---
  'execve':          ['process', function (a) { return readCStr(a[0]); }],
  'fork':            ['process', function (a) { return 'fork'; }],
  'CreateProcessW':  ['process', function (a) { return readWStr(a[1]); }],
  'WinExec':         ['process', function (a) { return readCStr(a[0]); }],
  'ShellExecuteW':   ['process', function (a) { return readWStr(a[2]); }],
  'WriteProcessMemory':['process',function (a){ return 'remote-write'; }],
  'CreateRemoteThread':['process',function (a){ return 'remote-thread'; }],
  'ptrace':          ['process', function (a) { return 'req=' + a[0]; }],

  // --- registry ---
  'RegSetValueExW':  ['registry',function (a) { return readWStr(a[1]); }],
  'RegCreateKeyExW': ['registry',function (a) { return readWStr(a[1]); }],

  // --- crypto ---
  'CryptEncrypt':    ['crypto',  function (a) { return 'CryptEncrypt'; }],
  'EVP_EncryptInit_ex':['crypto',function (a){ return 'EVP_EncryptInit'; }],
  'BCryptEncrypt':   ['crypto',  function (a) { return 'BCryptEncrypt'; }]
};

var installed = 0;
Object.keys(HOOKS).forEach(function (name) {
  var cat = HOOKS[name][0];
  var fmt = HOOKS[name][1];
  var addr = Module.findExportByName(null, name);
  if (addr === null) return;
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        emit(cat, name, fmt(args));
      }
    });
    installed++;
  } catch (e) { /* symbol not hookable */ }
});

emit('meta', 'binscope-tracer', 'hooks=' + installed);
