// Generated from a transcript recorded by windbg-mcp 0.22.0+g667d9552-dirty.394b0b73 on 2026-10-10:
// a launched cmd.exe breaking on kernelbase!CreateFileW. Each call's arguments and typed result, unedited.

export type RecordedCall = { tool: string; args: Record<string, unknown>; ok: boolean; data: Record<string, unknown> | null }

export const RECORDED: RecordedCall[] = [
 {
  "tool": "launch",
  "args": {
   "command_line": "C:\\Windows\\System32\\cmd.exe /c type C:\\Windows\\win.ini"
  },
  "ok": true,
  "data": {
   "kind": "launch",
   "report": "r\nrax=0000000000000000 rbx=000000a08854f5c0 rcx=00007ffedc561264\nrdx=0000000000000000 rsi=00007ffedc59b938 rdi=000000a0886ad000\nrip=00007ffedc522239 rsp=000000a08854f020 rbp=0000000000000000\n r8=000000a08854f018  r9=0000000000000000 r10=0000000000000000\nr11=0000000000000246 r12=0000000000000000 r13=000001ff48170000\nr14=00007ffedc5788c0 r15=0000000000000040\niopl=0         nv up ei pl zr na pe nc\ncs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246\nntdll!LdrpDoDebuggerBreak+0x35:\n00007ffe`dc522239 cc              int     3\n\n5 module(s) loaded, `cmd` at 0x00007ff72f890000.\n  `modules` lists a page of that table and `modules { \"filter\": \"<name>\" }` answers for one.",
   "session_id": "sess-18dd16613e6a0bfc-1",
   "status": "ok",
   "summary": {
    "kernel_mode": false,
    "modules_loaded": 5,
    "primary_module": {
     "checksum": 361501,
     "end": "0x00007ff72f900000",
     "image_name": "cmd.exe",
     "name": "cmd",
     "size": 458752,
     "start": "0x00007ff72f890000",
     "symbols": "deferred",
     "timestamp": 2023704150,
     "user_mode": true
    }
   },
   "target": "C:\\Windows\\System32\\cmd.exe /c type C:\\Windows\\win.ini"
  }
 },
 {
  "tool": "set_breakpoint",
  "args": {
   "expression": "kernelbase!CreateFileW",
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "breakpoint": {
    "address": "0x00007ffed96277f0",
    "deferred": false,
    "enabled": true,
    "expression": "kernelbase!CreateFileW",
    "id": 0,
    "kind": "code",
    "one_shot": false,
    "pass_count": 1,
    "passes_remaining": 1
   },
   "breakpoints": [
    {
     "address": "0x00007ffed96277f0",
     "deferred": false,
     "enabled": true,
     "expression": "kernelbase!CreateFileW",
     "id": 0,
     "kind": "code",
     "one_shot": false,
     "pass_count": 1,
     "passes_remaining": 1
    }
   ],
   "cut_short": false,
   "status": "ok"
  }
 },
 {
  "tool": "go",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "command": "g",
   "interrupted": false,
   "output": "g\nModLoad: 00007ffe`d8b50000 00007ffe`d8bba000   C:\\Windows\\System32\\Wldp.dll\nModLoad: 00007ffe`d9fe0000 00007ffe`da083000   C:\\WINDOWS\\System32\\msvcp_win.dll\nModLoad: 00007ffe`db020000 00007ffe`db3a5000   C:\\WINDOWS\\System32\\combase.dll\nModLoad: 00007ffe`daa90000 00007ffe`daba8000   C:\\WINDOWS\\System32\\RPCRT4.dll\nonecore\\base\\ngscb\\wldp\\dll\\applicationsetting.cpp(1097)\\Wldp.dll!00007FFED8B8CEC4: (caller: 00007FF72F8B4B35) ReturnNt(1) tid(33e8) C0000225 The object was not found.\r\nBreakpoint 0 hit\n",
   "status": "ok",
   "stopped_at": "0x00007ffed96277f0",
   "target_gone": false,
   "thread": 13288,
   "timed_out": false
  }
 },
 {
  "tool": "registers",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "all_registers": false,
   "instruction_pointer": "0x00007ffed96277f0",
   "registers": [
    {
     "kind": "int",
     "name": "rax",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "rcx",
     "value": "0x000001ff4826f7f0"
    },
    {
     "kind": "int",
     "name": "rdx",
     "value": "0x0000000080000000"
    },
    {
     "kind": "int",
     "name": "rbx",
     "value": "0x0000000000000003"
    },
    {
     "kind": "int",
     "name": "rsp",
     "value": "0x000000a08854dd28"
    },
    {
     "kind": "int",
     "name": "rbp",
     "value": "0x000000a08854dda0"
    },
    {
     "kind": "int",
     "name": "rsi",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "rdi",
     "value": "0x0000000080000000"
    },
    {
     "kind": "int",
     "name": "r8",
     "value": "0x0000000000000003"
    },
    {
     "kind": "int",
     "name": "r9",
     "value": "0x000000a08854dd80"
    },
    {
     "kind": "int",
     "name": "r10",
     "value": "0x00007ffed9e80000"
    },
    {
     "kind": "int",
     "name": "r11",
     "value": "0x00007ffed9f6df31"
    },
    {
     "kind": "int",
     "name": "r12",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "r13",
     "value": "0xffffffffffffffff"
    },
    {
     "kind": "int",
     "name": "r14",
     "value": "0x0000000000000003"
    },
    {
     "kind": "int",
     "name": "r15",
     "value": "0x000001ff4826f7f0"
    },
    {
     "kind": "int",
     "name": "rip",
     "value": "0x00007ffed96277f0"
    },
    {
     "kind": "int",
     "name": "efl",
     "value": "0x0000000000000297"
    },
    {
     "kind": "int",
     "name": "cs",
     "value": "0x0000000000000033"
    },
    {
     "kind": "int",
     "name": "ds",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "es",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "fs",
     "value": "0x0000000000000053"
    },
    {
     "kind": "int",
     "name": "gs",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "ss",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "dr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr2",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr3",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr6",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr7",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "fpcw",
     "value": "0x000000000000027f"
    },
    {
     "kind": "int",
     "name": "fpsw",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "fptw",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "mxcsr",
     "value": "0x0000000000001f80"
    },
    {
     "kind": "int",
     "name": "exfrom",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "exto",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "brfrom",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "brto",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "ssp",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "cetumsr",
     "value": "0x0000000000000000"
    }
   ],
   "status": "ok"
  }
 },
 {
  "tool": "disassemble",
  "args": {
   "count": 10,
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "instructions": [
    {
     "address": "0x00007ffed96277f0",
     "bytes": "488bc4",
     "module": "KERNELBASE",
     "rva": "0x277f0",
     "text": "mov rax,rsp"
    },
    {
     "address": "0x00007ffed96277f3",
     "bytes": "48895808",
     "module": "KERNELBASE",
     "rva": "0x277f3",
     "text": "mov qword ptr [rax+8],rbx"
    },
    {
     "address": "0x00007ffed96277f7",
     "bytes": "48896810",
     "module": "KERNELBASE",
     "rva": "0x277f7",
     "text": "mov qword ptr [rax+10h],rbp"
    },
    {
     "address": "0x00007ffed96277fb",
     "bytes": "48897018",
     "module": "KERNELBASE",
     "rva": "0x277fb",
     "text": "mov qword ptr [rax+18h],rsi"
    },
    {
     "address": "0x00007ffed96277ff",
     "bytes": "48897820",
     "module": "KERNELBASE",
     "rva": "0x277ff",
     "text": "mov qword ptr [rax+20h],rdi"
    },
    {
     "address": "0x00007ffed9627803",
     "bytes": "4156",
     "module": "KERNELBASE",
     "rva": "0x27803",
     "text": "push r14"
    },
    {
     "address": "0x00007ffed9627805",
     "bytes": "4883ec50",
     "module": "KERNELBASE",
     "rva": "0x27805",
     "text": "sub rsp,50h"
    },
    {
     "address": "0x00007ffed9627809",
     "bytes": "448bb42480000000",
     "module": "KERNELBASE",
     "rva": "0x27809",
     "text": "mov r14d,dword ptr [rsp+80h]"
    },
    {
     "address": "0x00007ffed9627811",
     "bytes": "488bf9",
     "module": "KERNELBASE",
     "rva": "0x27811",
     "text": "mov rdi,rcx"
    },
    {
     "address": "0x00007ffed9627814",
     "bytes": "8b8c2488000000",
     "module": "KERNELBASE",
     "rva": "0x27814",
     "text": "mov ecx,dword ptr [rsp+88h]"
    }
   ],
   "start": "0x00007ffed96277f0",
   "status": "ok",
   "stopped_early": false
  }
 },
 {
  "tool": "backtrace",
  "args": {
   "frames": 8,
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "frames": [
    {
     "address": "0x00007ffed96277f0",
     "displacement": "0x0",
     "index": 0,
     "module": "KERNELBASE",
     "rva": "0x277f0",
     "symbol": "KERNELBASE!CreateFileW"
    },
    {
     "address": "0x00007ff72f89f823",
     "displacement": "0x9f",
     "index": 1,
     "module": "cmd",
     "rva": "0xf823",
     "symbol": "cmd!Copen_Work"
    },
    {
     "address": "0x00007ff72f8a155d",
     "displacement": "0xcd",
     "index": 2,
     "module": "cmd",
     "rva": "0x1155d",
     "symbol": "cmd!TyWork"
    },
    {
     "address": "0x00007ff72f8a9ca2",
     "displacement": "0x32a",
     "index": 3,
     "module": "cmd",
     "rva": "0x19ca2",
     "symbol": "cmd!LoopThroughArgs"
    },
    {
     "address": "0x00007ff72f8c2f5a",
     "displacement": "0x1a",
     "index": 4,
     "module": "cmd",
     "rva": "0x32f5a",
     "symbol": "cmd!eType"
    },
    {
     "address": "0x00007ff72f898dbf",
     "displacement": "0x30f",
     "index": 5,
     "module": "cmd",
     "rva": "0x8dbf",
     "symbol": "cmd!FindFixAndRun"
    },
    {
     "address": "0x00007ff72f89eba3",
     "displacement": "0x163",
     "index": 6,
     "module": "cmd",
     "rva": "0xeba3",
     "symbol": "cmd!Dispatch"
    },
    {
     "address": "0x00007ff72f8c3e81",
     "displacement": "0x1a9",
     "index": 7,
     "module": "cmd",
     "rva": "0x33e81",
     "symbol": "cmd!main"
    }
   ],
   "frames_truncated": true,
   "status": "ok"
  }
 },
 {
  "tool": "read_memory",
  "args": {
   "address": "0x000001ff4826f7f0",
   "session_id": "sess-18dd16613e6a0bfc-1",
   "size": 96
  },
  "ok": true,
  "data": {
   "address": "0x000001ff4826f7f0",
   "data": "43003a005c00570069006e0064006f00770073005c00770069006e002e0069006e006900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
   "read_size": 96,
   "requested_size": 96,
   "status": "ok"
  }
 },
 {
  "tool": "step_over",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "command": "p",
   "interrupted": false,
   "output": "p\n",
   "status": "ok",
   "stopped_at": "0x00007ffed96277f3",
   "target_gone": false,
   "thread": 13288,
   "timed_out": false
  }
 },
 {
  "tool": "step_over",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "command": "p",
   "interrupted": false,
   "output": "p\n",
   "status": "ok",
   "stopped_at": "0x00007ffed96277f7",
   "target_gone": false,
   "thread": 13288,
   "timed_out": false
  }
 },
 {
  "tool": "step_over",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "command": "p",
   "interrupted": false,
   "output": "p\n",
   "status": "ok",
   "stopped_at": "0x00007ffed96277fb",
   "target_gone": false,
   "thread": 13288,
   "timed_out": false
  }
 },
 {
  "tool": "step_over",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "command": "p",
   "interrupted": false,
   "output": "p\n",
   "status": "ok",
   "stopped_at": "0x00007ffed96277ff",
   "target_gone": false,
   "thread": 13288,
   "timed_out": false
  }
 },
 {
  "tool": "registers",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "all_registers": false,
   "instruction_pointer": "0x00007ffed96277ff",
   "registers": [
    {
     "kind": "int",
     "name": "rax",
     "value": "0x000000a08854dd28"
    },
    {
     "kind": "int",
     "name": "rcx",
     "value": "0x000001ff4826f7f0"
    },
    {
     "kind": "int",
     "name": "rdx",
     "value": "0x0000000080000000"
    },
    {
     "kind": "int",
     "name": "rbx",
     "value": "0x0000000000000003"
    },
    {
     "kind": "int",
     "name": "rsp",
     "value": "0x000000a08854dd28"
    },
    {
     "kind": "int",
     "name": "rbp",
     "value": "0x000000a08854dda0"
    },
    {
     "kind": "int",
     "name": "rsi",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "rdi",
     "value": "0x0000000080000000"
    },
    {
     "kind": "int",
     "name": "r8",
     "value": "0x0000000000000003"
    },
    {
     "kind": "int",
     "name": "r9",
     "value": "0x000000a08854dd80"
    },
    {
     "kind": "int",
     "name": "r10",
     "value": "0x00007ffed9e80000"
    },
    {
     "kind": "int",
     "name": "r11",
     "value": "0x00007ffed9f6df31"
    },
    {
     "kind": "int",
     "name": "r12",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "r13",
     "value": "0xffffffffffffffff"
    },
    {
     "kind": "int",
     "name": "r14",
     "value": "0x0000000000000003"
    },
    {
     "kind": "int",
     "name": "r15",
     "value": "0x000001ff4826f7f0"
    },
    {
     "kind": "int",
     "name": "rip",
     "value": "0x00007ffed96277ff"
    },
    {
     "kind": "int",
     "name": "efl",
     "value": "0x0000000000000297"
    },
    {
     "kind": "int",
     "name": "cs",
     "value": "0x0000000000000033"
    },
    {
     "kind": "int",
     "name": "ds",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "es",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "fs",
     "value": "0x0000000000000053"
    },
    {
     "kind": "int",
     "name": "gs",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "ss",
     "value": "0x000000000000002b"
    },
    {
     "kind": "int",
     "name": "dr0",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr1",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr2",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr3",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr6",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "dr7",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "fpcw",
     "value": "0x000000000000027f"
    },
    {
     "kind": "int",
     "name": "fpsw",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "fptw",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "mxcsr",
     "value": "0x0000000000001f80"
    },
    {
     "kind": "int",
     "name": "exfrom",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "exto",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "brfrom",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "brto",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "ssp",
     "value": "0x0000000000000000"
    },
    {
     "kind": "int",
     "name": "cetumsr",
     "value": "0x0000000000000000"
    }
   ],
   "status": "ok"
  }
 },
 {
  "tool": "disassemble",
  "args": {
   "count": 6,
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "instructions": [
    {
     "address": "0x00007ffed96277ff",
     "bytes": "48897820",
     "module": "KERNELBASE",
     "rva": "0x277ff",
     "text": "mov qword ptr [rax+20h],rdi"
    },
    {
     "address": "0x00007ffed9627803",
     "bytes": "4156",
     "module": "KERNELBASE",
     "rva": "0x27803",
     "text": "push r14"
    },
    {
     "address": "0x00007ffed9627805",
     "bytes": "4883ec50",
     "module": "KERNELBASE",
     "rva": "0x27805",
     "text": "sub rsp,50h"
    },
    {
     "address": "0x00007ffed9627809",
     "bytes": "448bb42480000000",
     "module": "KERNELBASE",
     "rva": "0x27809",
     "text": "mov r14d,dword ptr [rsp+80h]"
    },
    {
     "address": "0x00007ffed9627811",
     "bytes": "488bf9",
     "module": "KERNELBASE",
     "rva": "0x27811",
     "text": "mov rdi,rcx"
    },
    {
     "address": "0x00007ffed9627814",
     "bytes": "8b8c2488000000",
     "module": "KERNELBASE",
     "rva": "0x27814",
     "text": "mov ecx,dword ptr [rsp+88h]"
    }
   ],
   "start": "0x00007ffed96277ff",
   "status": "ok",
   "stopped_early": false
  }
 },
 {
  "tool": "go",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "command": "g",
   "interrupted": false,
   "output": "g\nModLoad: 00007ffe`d8290000 00007ffe`d82ab000   C:\\WINDOWS\\SYSTEM32\\kernel.appcore.dll\nModLoad: 00007ffe`daea0000 00007ffe`daf49000   C:\\WINDOWS\\System32\\msvcrt.dll\n",
   "status": "ok",
   "target_gone": true,
   "timed_out": false
  }
 },
 {
  "tool": "end_session",
  "args": {
   "session_id": "sess-18dd16613e6a0bfc-1"
  },
  "ok": true,
  "data": {
   "recovery_required": false,
   "released": true,
   "session_id": "sess-18dd16613e6a0bfc-1",
   "status": "ok",
   "target_left_running": false,
   "worker_terminated": true
  }
 }
]
