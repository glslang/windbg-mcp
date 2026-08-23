# Walking a structure (`walk_memory`)

Walking a kernel list through `execute` is all-or-nothing. A single unmapped dereference inside a
MASM `.for` loop ends the whole script with `An unexpected exception was raised (0x80040205)` — no
rows, no iteration number, no indication of how many nodes were classified before it. In pool and
use-after-free work that is precisely backwards: "some of these nodes are freed" is the normal case,
and the pointer that will not read is usually the one worth looking at
([#103](https://github.com/glslang/windbg-mcp/issues/103)).

`walk_memory` reads each value on its own, so a hole is a row rather than an end. Three ways to name
the nodes, one of them required:

| | |
|---|---|
| `addresses` | walk these exactly — the bulk read |
| `start` + `stride` | an array: element *i* is `start + i * stride` |
| `start` + `next_offset` | a chain: the next node is the pointer at `node + next_offset` |

`fields` says what to read out of each node (`{name, offset, size}`, size 1/2/4/8, **offsets may be
negative** — a pool header sits 16 bytes before the address the allocator returned). `start` is any
expression `?` evaluates, so a symbol or `poi(<head>)` works; the addresses in a list are numbers, in
any form the debugger prints. Fields of one structure are fetched in a single read and fall back to
per-field reads only where there is a hole, so a node costs one round trip in the ordinary case —
which is what lets a 512-node walk finish over KDNET.

```jsonc
// Every message pointer in a 512-slot handle table, freed ones included.
{ "start": "MessageManager!g_Handles", "stride": 16, "count": 512,
  "fields": [{ "name": "msg", "offset": 8 }] }

// Then the refcount out of each of those pointers — one call, holes and all.
{ "addresses": ["0xffffc00f6ec02f90", "0xffffc00f6ec03000", …],
  "fields": [{ "name": "refs", "offset": 16, "size": 4 },
             { "name": "flink", "offset": 0 }] }
```

An unreadable value comes back as `null` in its own field (`0x????????????????` in the text), a node
where *nothing* read is counted, and the walk carries on — for a list or an array. A **chain** is the
exception, because the address of everything after an unreadable node lived in the bytes that would
not read: it stops and says which node. It also stops on a null link, on a **loop** (reporting where
the list closed — back at the head that is a healthy circular `_LIST_ENTRY`, anywhere else it is
corruption), and at `count`, where it hands back the address to resume from. `count` past the cap of
1024 is refused rather than clamped, so "every node asked for was visited" is never about a number
this server lowered.
