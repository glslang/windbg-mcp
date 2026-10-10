// Recorded 2026-10-10 from docs/samples/082126-7015-01.dmp (HEVD 0x139, ARM64 kernel)
// through windbg-mcp 0.22.0 dev build. Payloads as received; only the opener's prose report
// is cut to its version line. This target is ARM64, so its registers are x0.. and not rax...

import type { RecordedCall } from './recorded'

export const RECORDED_DUMP: RecordedCall[] = [
 {
  "tool": "open_dump",
  "args": {
   "path": "C:/workspace/windbg-mcp/docs/samples/082126-7015-01.dmp"
  },
  "ok": true,
  "data": {
   "kind": "dump",
   "report": "Windows 10 Kernel Version 26100 MP (4 procs) Free ARM 64-bit (AArch64)\n",
   "session_id": "sess-18dd24027dc6f554-1",
   "status": "ok",
   "summary": {
    "bug_check": {
     "code": "0x139",
     "name": "KERNEL_SECURITY_CHECK_FAILURE",
     "parameters": [
      "0x0000000000000002",
      "0xffff860d17ea1190",
      "0xffff860d17ea1048",
      "0x0000000000000000"
     ]
    },
    "kernel_mode": true,
    "kernel_target": "windows",
    "modules_loaded": 181,
    "primary_module": {
     "checksum": 11584734,
     "end": "0xfffff802eae4a000",
     "image_name": "ntkrnlmp.exe",
     "loaded_image_name": "C:\\workspace\\windbg-mcp\\target\\debug\\sym\\ntkrnlmp.exe\\00587F24124a000\\ntkrnlmp.exe",
     "name": "nt",
     "pdb": {
      "age": 1,
      "guid": "423860BC064B27DFDB7F027CD5B058A6",
      "key": "<redacted>"
     },
     "size": 19177472,
     "start": "0xfffff802e9c00000",
     "symbols": "pdb",
     "timestamp": 5799716,
     "user_mode": false
    }
   },
   "target": "C:/workspace/windbg-mcp/docs/samples/082126-7015-01.dmp"
  }
 },
 {
  "tool": "crash_triage",
  "args": {
   "frames": 16,
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "analysis": {
    "bug_check_name": "KERNEL_SECURITY_CHECK_FAILURE",
    "command": "!analyze -v",
    "failure_bucket_id": "0x139_MISSING_GSFRAME_HEVD!unknown_function",
    "image_name": "HEVD.sys",
    "module_name": "HEVD",
    "parameter_notes": [
     "Stack cookie instrumentation code detected a stack-based",
     "Address of the trap frame for the exception that caused the BugCheck",
     "Address of the exception record for the exception that caused the BugCheck",
     "Reserved"
    ],
    "process_name": "powershell.exe",
    "ran": true,
    "truncated": false
   },
   "bug_check": {
    "code": "0x139",
    "name": "KERNEL_SECURITY_CHECK_FAILURE",
    "parameters": [
     "0x0000000000000002",
     "0xffff860d17ea1190",
     "0xffff860d17ea1048",
     "0x0000000000000000"
    ]
   },
   "faulting_frame": {
    "address": "0xfffff802e69010dc",
    "index": 9,
    "module": "HEVD",
    "rva": "0x10dc"
   },
   "frames": [
    {
     "address": "0xfffff802e9e5d5ac",
     "displacement": "0x32c",
     "index": 0,
     "module": "nt",
     "rva": "0x25d5ac",
     "symbol": "nt!KeBugCheck2"
    },
    {
     "address": "0xfffff802e9e5df74",
     "displacement": "0x14",
     "index": 1,
     "module": "nt",
     "rva": "0x25df74",
     "symbol": "nt!KeBugCheckEx"
    },
    {
     "address": "0xfffff802ea1140ec",
     "displacement": "0xac",
     "index": 2,
     "module": "nt",
     "rva": "0x5140ec",
     "symbol": "nt!KiDispatchFastFail"
    },
    {
     "address": "0xfffff802e9e8dc74",
     "displacement": "0x184",
     "index": 3,
     "module": "nt",
     "rva": "0x28dc74",
     "symbol": "nt!KiPreprocessInternalBreakpoint"
    },
    {
     "address": "0xfffff802e9e8da04",
     "displacement": "0x64",
     "index": 4,
     "module": "nt",
     "rva": "0x28da04",
     "symbol": "nt!KiPreprocessFault"
    },
    {
     "address": "0xfffff802e9e6c3e4",
     "displacement": "0x2a4",
     "index": 5,
     "module": "nt",
     "rva": "0x26c3e4",
     "symbol": "nt!KiDispatchException"
    },
    {
     "address": "0xfffff802e9eb93ac",
     "displacement": "0xdc",
     "index": 6,
     "module": "nt",
     "rva": "0x2b93ac",
     "symbol": "nt!KiSynchronousException"
    },
    {
     "address": "0xfffff802ea23bc60",
     "displacement": "0x24",
     "index": 7,
     "module": "nt",
     "rva": "0x63bc60",
     "symbol": "nt!KzSynchronousException"
    },
    {
     "address": "0xfffff802ea23a85c",
     "displacement": "0x5c",
     "index": 8,
     "module": "nt",
     "rva": "0x63a85c",
     "symbol": "nt!KiArm64ExceptionVectors"
    },
    {
     "address": "0xfffff802e69010dc",
     "index": 9,
     "module": "HEVD",
     "rva": "0x10dc"
    },
    {
     "address": "0xfffff802e6901020",
     "index": 10,
     "module": "HEVD",
     "rva": "0x1020"
    }
   ],
   "frames_truncated": false,
   "process_name": "powershell.exe",
   "status": "ok"
  }
 },
 {
  "tool": "modules",
  "args": {
   "limit": 12,
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "loaded": 181,
   "matched": 181,
   "modules": [
    {
     "checksum": 80168,
     "end": "0xfffff802e3363000",
     "image_name": "kdcom.dll",
     "name": "kdcom",
     "size": 77824,
     "start": "0xfffff802e3350000",
     "symbols": "deferred",
     "timestamp": 2778998941,
     "user_mode": false
    },
    {
     "checksum": 101667,
     "end": "0xfffff802e337f000",
     "image_name": "symcryptk.dll",
     "name": "symcryptk",
     "size": 61440,
     "start": "0xfffff802e3370000",
     "symbols": "deferred",
     "timestamp": 339421799,
     "user_mode": false
    },
    {
     "checksum": 215439,
     "end": "0xfffff802e33b8000",
     "image_name": "tm.sys",
     "name": "tm",
     "size": 163840,
     "start": "0xfffff802e3390000",
     "symbols": "deferred",
     "timestamp": 3137223421,
     "user_mode": false
    },
    {
     "checksum": 525932,
     "end": "0xfffff802e3447000",
     "image_name": "CLFS.SYS",
     "name": "CLFS",
     "size": 552960,
     "start": "0xfffff802e33c0000",
     "symbols": "deferred",
     "timestamp": 200307652,
     "user_mode": false
    },
    {
     "checksum": 824201,
     "end": "0xfffff802e351b000",
     "image_name": "cng.sys",
     "name": "cng",
     "size": 831488,
     "start": "0xfffff802e3450000",
     "symbols": "deferred",
     "timestamp": 3351426961,
     "user_mode": false
    },
    {
     "checksum": 78897,
     "end": "0xfffff802e3534000",
     "image_name": "winaccel.sys",
     "name": "winaccel",
     "size": 81920,
     "start": "0xfffff802e3520000",
     "symbols": "deferred",
     "timestamp": 4046206241,
     "user_mode": false
    }
   ],
   "status": "ok",
   "unloaded": [
    {
     "checksum": 0,
     "end": "0xfffff802e8642000",
     "image_name": "NetworkPriva",
     "name": "",
     "size": 139264,
     "start": "0xfffff802e8620000",
     "symbols": "none",
     "timestamp": 0,
     "unloaded": true,
     "user_mode": false
    },
    {
     "checksum": 0,
     "end": "0xfffff802e6f07000",
     "image_name": "dump_storpor",
     "name": "",
     "size": 94208,
     "start": "0xfffff802e6ef0000",
     "symbols": "none",
     "timestamp": 0,
     "unloaded": true,
     "user_mode": false
    },
    {
     "checksum": 0,
     "end": "0xfffff802e6f85000",
     "image_name": "dump_storahc",
     "name": "",
     "size": 217088,
     "start": "0xfffff802e6f50000",
     "symbols": "none",
     "timestamp": 0,
     "unloaded": true,
     "user_mode": false
    },
    {
     "checksum": 0,
     "end": "0xfffff802e6fe5000",
     "image_name": "dump_dumpfve",
     "name": "",
     "size": 151552,
     "start": "0xfffff802e6fc0000",
     "symbols": "none",
     "timestamp": 0,
     "unloaded": true,
     "user_mode": false
    },
    {
     "checksum": 0,
     "end": "0xfffff802e708e000",
     "image_name": "prl_pl011.sy",
     "name": "",
     "size": 122880,
     "start": "0xfffff802e7070000",
     "symbols": "none",
     "timestamp": 0,
     "unloaded": true,
     "user_mode": false
    },
    {
     "checksum": 0,
     "end": "0xfffff802e6b13000",
     "image_name": "WUDFRd.sys",
     "name": "",
     "size": 405504,
     "start": "0xfffff802e6ab0000",
     "symbols": "none",
     "timestamp": 0,
     "unloaded": true,
     "user_mode": false
    }
   ],
   "unloaded_matched": 8
  }
 },
 {
  "tool": "registers",
  "args": {
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "all_registers": false,
   "instruction_pointer": "0xfffff802e9e5d5ac",
   "registers": [
    {
     "kind": "int",
     "name": "x0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "x1",
     "value": "0x0000000000000005"
    },
    {
     "kind": "int",
     "name": "x2",
     "value": "0x0000000000000002"
    },
    {
     "kind": "int",
     "name": "x3",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "x4",
     "value": "0xffff860d17ea03c8"
    },
    {
     "kind": "int",
     "name": "x5",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "x6",
     "value": "0x0000000000000080"
    },
    {
     "kind": "int",
     "name": "x7",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "x8",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "x9",
     "value": "0xfffff802ea985944"
    },
    {
     "kind": "int",
     "name": "x10",
     "value": "0x0000000000000005"
    },
    {
     "kind": "int",
     "name": "x11",
     "value": "0xffff860d17ea2000"
    },
    {
     "kind": "int",
     "name": "x12",
     "value": "0xffff860d17ea0e80"
    },
    {
     "kind": "int",
     "name": "x13",
     "value": "0xb882c0656f202f69"
    },
    {
     "kind": "int",
     "name": "x14",
     "value": "0x0000000000000010"
    },
    {
     "kind": "int",
     "name": "x15",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "x16",
     "value": "0x00000e10d3ffcae6"
    },
    {
     "kind": "int",
     "name": "x17",
     "value": "0x00000e10d3ffcae6"
    },
    {
     "kind": "int",
     "name": "x18",
     "value": "0xffffe70160c60000"
    },
    {
     "kind": "int",
     "name": "x19",
     "value": "0xfffff802ea997dc0"
    },
    {
     "kind": "int",
     "name": "x20",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "x21",
     "value": "0x000071f5d2afde20"
    },
    {
     "kind": "int",
     "name": "x22",
     "value": "0xffffe70160c60980"
    },
    {
     "kind": "int",
     "name": "x23",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "x24",
     "value": "0x0000000000000002"
    },
    {
     "kind": "int",
     "name": "x25",
     "value": "0xffff860d17ea2000"
    },
    {
     "kind": "int",
     "name": "x26",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "x27",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "x28",
     "value": "0x000001ff5dcd7498"
    },
    {
     "kind": "int",
     "name": "fp",
     "value": "0xffff860d17ea0400"
    },
    {
     "kind": "int",
     "name": "lr",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "sp",
     "value": "0xffff860d17ea03f0"
    },
    {
     "kind": "int",
     "name": "pc",
     "value": "0xfffff802e9e5d5ac"
    },
    {
     "kind": "int",
     "name": "cpsr",
     "value": "0x0000000000000144"
    },
    {
     "kind": "int",
     "name": "elr",
     "value": "0xfffff802e69010dc"
    },
    {
     "kind": "int",
     "name": "spsr",
     "value": "0x00000000a0000144"
    },
    {
     "kind": "int",
     "name": "w0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "w1",
     "value": "0x0000000000000005"
    },
    {
     "kind": "int",
     "name": "w2",
     "value": "0x0000000000000002"
    },
    {
     "kind": "int",
     "name": "w3",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "w4",
     "value": "0x0000000017ea03c8"
    },
    {
     "kind": "int",
     "name": "w5",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "w6",
     "value": "0x0000000000000080"
    },
    {
     "kind": "int",
     "name": "w7",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "w8",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "w9",
     "value": "0x00000000ea985944"
    },
    {
     "kind": "int",
     "name": "w10",
     "value": "0x0000000000000005"
    },
    {
     "kind": "int",
     "name": "w11",
     "value": "0x0000000017ea2000"
    },
    {
     "kind": "int",
     "name": "w12",
     "value": "0x0000000017ea0e80"
    },
    {
     "kind": "int",
     "name": "w13",
     "value": "0x000000006f202f69"
    },
    {
     "kind": "int",
     "name": "w14",
     "value": "0x0000000000000010"
    },
    {
     "kind": "int",
     "name": "w15",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "w16",
     "value": "0x00000000d3ffcae6"
    },
    {
     "kind": "int",
     "name": "w17",
     "value": "0x00000000d3ffcae6"
    },
    {
     "kind": "int",
     "name": "w18",
     "value": "0x0000000060c60000"
    },
    {
     "kind": "int",
     "name": "w19",
     "value": "0x00000000ea997dc0"
    },
    {
     "kind": "int",
     "name": "w20",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "w21",
     "value": "0x00000000d2afde20"
    },
    {
     "kind": "int",
     "name": "w22",
     "value": "0x0000000060c60980"
    },
    {
     "kind": "int",
     "name": "w23",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "w24",
     "value": "0x0000000000000002"
    },
    {
     "kind": "int",
     "name": "w25",
     "value": "0x0000000017ea2000"
    },
    {
     "kind": "int",
     "name": "w26",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "w27",
     "value": "0x0000000000000001"
    },
    {
     "kind": "int",
     "name": "w28",
     "value": "0x000000005dcd7498"
    },
    {
     "kind": "int",
     "name": "w29",
     "value": "0x0000000017ea0400"
    },
    {
     "kind": "int",
     "name": "w30",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "fpsr",
     "value": "0x0000000000000010"
    },
    {
     "kind": "int",
     "name": "fpcr",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr2",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr3",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr4",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr5",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr6",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bvr7",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr2",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr3",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr4",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr5",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr6",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "bcr7",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "wvr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "wvr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "wcr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "wcr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr2",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr3",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr4",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr5",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr6",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbvr7",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbcr0",
     "value": "0x00000000000001e0"
    },
    {
     "kind": "int",
     "name": "kbcr1",
     "value": "0x00000000000001e0"
    },
    {
     "kind": "int",
     "name": "kbcr2",
     "value": "0x00000000000001e0"
    },
    {
     "kind": "int",
     "name": "kbcr3",
     "value": "0x00000000000001e0"
    },
    {
     "kind": "int",
     "name": "kbcr4",
     "value": "0x00000000000001e0"
    },
    {
     "kind": "int",
     "name": "kbcr5",
     "value": "0x00000000000001e0"
    },
    {
     "kind": "int",
     "name": "kbcr6",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kbcr7",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kwvr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kwvr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kwcr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "kwcr1",
     "value": "0x0000000000000000"
    }
   ],
   "status": "ok"
  }
 },
 {
  "tool": "backtrace",
  "args": {
   "frames": 12,
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "frames": [
    {
     "address": "0xfffff802e9e5d5ac",
     "displacement": "0x32c",
     "index": 0,
     "module": "nt",
     "rva": "0x25d5ac",
     "symbol": "nt!KeBugCheck2"
    },
    {
     "address": "0xfffff802e9e5df74",
     "displacement": "0x14",
     "index": 1,
     "module": "nt",
     "rva": "0x25df74",
     "symbol": "nt!KeBugCheckEx"
    },
    {
     "address": "0xfffff802ea1140ec",
     "displacement": "0xac",
     "index": 2,
     "module": "nt",
     "rva": "0x5140ec",
     "symbol": "nt!KiDispatchFastFail"
    },
    {
     "address": "0xfffff802e9e8dc74",
     "displacement": "0x184",
     "index": 3,
     "module": "nt",
     "rva": "0x28dc74",
     "symbol": "nt!KiPreprocessInternalBreakpoint"
    },
    {
     "address": "0xfffff802e9e8da04",
     "displacement": "0x64",
     "index": 4,
     "module": "nt",
     "rva": "0x28da04",
     "symbol": "nt!KiPreprocessFault"
    },
    {
     "address": "0xfffff802e9e6c3e4",
     "displacement": "0x2a4",
     "index": 5,
     "module": "nt",
     "rva": "0x26c3e4",
     "symbol": "nt!KiDispatchException"
    },
    {
     "address": "0xfffff802e9eb93ac",
     "displacement": "0xdc",
     "index": 6,
     "module": "nt",
     "rva": "0x2b93ac",
     "symbol": "nt!KiSynchronousException"
    },
    {
     "address": "0xfffff802ea23bc60",
     "displacement": "0x24",
     "index": 7,
     "module": "nt",
     "rva": "0x63bc60",
     "symbol": "nt!KzSynchronousException"
    },
    {
     "address": "0xfffff802ea23a85c",
     "displacement": "0x5c",
     "index": 8,
     "module": "nt",
     "rva": "0x63a85c",
     "symbol": "nt!KiArm64ExceptionVectors"
    },
    {
     "address": "0xfffff802e69010dc",
     "index": 9,
     "module": "HEVD",
     "rva": "0x10dc"
    },
    {
     "address": "0xfffff802e6901020",
     "index": 10,
     "module": "HEVD",
     "rva": "0x1020"
    }
   ],
   "frames_truncated": false,
   "status": "ok"
  }
 },
 {
  "tool": "disassemble",
  "args": {
   "address": "0xfffff802e9e5d5ac",
   "count": 12,
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "instructions": [
    {
     "address": "0xfffff802e9e5d5ac",
     "bytes": "910102c0",
     "module": "nt",
     "rva": "0x25d5ac",
     "text": "add x0,x22,#0x40"
    },
    {
     "address": "0xfffff802e9e5d5b0",
     "bytes": "94007178",
     "module": "nt",
     "rva": "0x25d5b0",
     "text": "bl nt!KiSaveProcessorControlState (fffff802e9e79b90)"
    },
    {
     "address": "0xfffff802e9e5d5b4",
     "bytes": "90005928",
     "module": "nt",
     "rva": "0x25d5b4",
     "text": "adrp x8,nt!PopSIdle+0x40 (fffff802ea981000)"
    },
    {
     "address": "0xfffff802e9e5d5b8",
     "bytes": "f9426909",
     "module": "nt",
     "rva": "0x25d5b8",
     "text": "ldr x9,[x8,#0x4D0]"
    },
    {
     "address": "0xfffff802e9e5d5bc",
     "bytes": "b9402bf5",
     "module": "nt",
     "rva": "0x25d5bc",
     "text": "ldr w21,[sp,#0x28]"
    },
    {
     "address": "0xfffff802e9e5d5c0",
     "bytes": "b5000069",
     "module": "nt",
     "rva": "0x25d5c0",
     "text": "cbnz x9,nt!KeBugCheck2+0x34c (fffff802e9e5d5cc)"
    },
    {
     "address": "0xfffff802e9e5d5c4",
     "bytes": "52800016",
     "module": "nt",
     "rva": "0x25d5c4",
     "text": "mov w22,#0"
    },
    {
     "address": "0xfffff802e9e5d5c8",
     "bytes": "14000017",
     "module": "nt",
     "rva": "0x25d5c8",
     "text": "b nt!KeBugCheck2+0x3a4 (fffff802e9e5d624)"
    },
    {
     "address": "0xfffff802e9e5d5cc",
     "bytes": "90005928",
     "module": "nt",
     "rva": "0x25d5cc",
     "text": "adrp x8,nt!PopSIdle+0x40 (fffff802ea981000)"
    },
    {
     "address": "0xfffff802e9e5d5d0",
     "bytes": "b9467108",
     "module": "nt",
     "rva": "0x25d5d0",
     "text": "ldr w8,[x8,#0x670]"
    },
    {
     "address": "0xfffff802e9e5d5d4",
     "bytes": "34000068",
     "module": "nt",
     "rva": "0x25d5d4",
     "text": "cbz w8,nt!KeBugCheck2+0x360 (fffff802e9e5d5e0)"
    },
    {
     "address": "0xfffff802e9e5d5d8",
     "bytes": "90005928",
     "module": "nt",
     "rva": "0x25d5d8",
     "text": "adrp x8,nt!PopSIdle+0x40 (fffff802ea981000)"
    }
   ],
   "start": "0xfffff802e9e5d5ac",
   "status": "ok",
   "stopped_early": false
  }
 },
 {
  "tool": "read_memory",
  "args": {
   "address": "0xfffff802e9e5d5ac",
   "session_id": "sess-18dd24027dc6f554-1",
   "size": 64
  },
  "ok": true,
  "data": {
   "address": "0xfffff802e9e5d5ac",
   "data": "c00201917871009428590090096942f9f52b40b9690000b5160080521700001428590090087146b968000034285900901f9929392809403908ffff34db010034",
   "read_size": 64,
   "requested_size": 64,
   "status": "ok"
  }
 },
 {
  "tool": "modules",
  "args": {
   "filter": "HEVD",
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "filter": "*HEVD*",
   "loaded": 181,
   "matched": 1,
   "modules": [
    {
     "checksum": 59577,
     "end": "0xfffff802e698f000",
     "image_name": "HEVD.sys",
     "loaded_image_name": "HEVD.sys",
     "name": "HEVD",
     "size": 585728,
     "start": "0xfffff802e6900000",
     "symbols": "none",
     "timestamp": 1734099220,
     "user_mode": false
    }
   ],
   "status": "ok",
   "unloaded": [],
   "unloaded_matched": 0
  }
 },
 {
  "tool": "end_session",
  "args": {
   "session_id": "sess-18dd24027dc6f554-1"
  },
  "ok": true,
  "data": {
   "recovery_required": false,
   "released": true,
   "session_id": "sess-18dd24027dc6f554-1",
   "status": "ok",
   "worker_terminated": true
  }
 }
]
