//! A function's listing as **blocks and edges**, which is what it already is.
//!
//! `uf` prints a function's basic blocks one after another, so a pass that reads the listing
//! straight through carries facts across seams control flow never crosses — the `pop r13` in a
//! shared epilogue, the block after a `ret` that is entered from a branch somewhere else. Every
//! such fact is a guard in whatever is reading it, and the guards are where the next defect lands
//! ([#306](https://github.com/glslang/windbg-mcp/issues/306)).
//!
//! What this module does is recover the structure the listing had before it was flattened: where
//! each block starts and ends, and which blocks each one can reach. Nothing here decides what an
//! instruction *means* — that is the caller's, and the point is that the caller gets to ask about
//! one block at a time, with the edges that reach it.
//!
//! # What an edge is, and is not
//!
//! An edge exists where the **encoding** says control can go: a fall-through, a direct branch's
//! two successors, a direct jump's one. An indirect transfer has none, and that is deliberate —
//! a guessed edge is the one thing a walk resting on this must never have. A target outside this
//! listing is not an edge either: it leaves the function, and this is a function's graph.
//!
//! An instruction that could not be read or decoded ends its block and has no successor, for the
//! same reason [`crate::driver`]'s walk stops at one: there is no instruction there, so there is
//! nothing after it.
//!
//! # Engine-free
//!
//! Like the analyses it serves, this takes decoded instructions and nothing else, so its tests are
//! hand-built listings with no debugger anywhere near them.

use std::collections::{BTreeSet, HashMap};

use dbgscope::dbgeng::{Flow, Instruction};

/// One basic block: a run of instructions with one entry and one exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Block {
    /// Index of the first instruction, into the listing this was built from.
    pub(crate) start: usize,
    /// Index one past the last.
    pub(crate) end: usize,
    /// The blocks control can reach from here, by index into [`Graph::blocks`].
    ///
    /// Empty for a block ending in a return, a trap, an indirect transfer, or an instruction that
    /// would not decode — and for one whose only destination is outside this function.
    pub(crate) successors: Vec<usize>,
}

/// A function's blocks, and the edges between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Graph {
    pub(crate) blocks: Vec<Block>,
    /// Which block each instruction index belongs to.
    by_instruction: Vec<usize>,
}

impl Graph {
    /// The block holding the instruction at `index`.
    pub(crate) fn holding(&self, index: usize) -> Option<usize> {
        self.by_instruction.get(index).copied()
    }

    /// The blocks in an order where a block follows the ones that reach it, wherever the graph
    /// allows.
    ///
    /// **A reverse post-order, not a topological sort**: a dispatch routine's graph has loops, and
    /// a sort that refused one would refuse the function. What this buys a fixed-point walk is the
    /// ordinary case converging in one sweep rather than in as many sweeps as the chain is long.
    pub(crate) fn walk_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.blocks.len());
        let mut seen = vec![false; self.blocks.len()];
        // An explicit stack rather than recursion: a long compare chain is a deep graph, and a
        // dispatch routine is exactly where one is.
        let mut stack = vec![(0usize, 0usize)];
        if self.blocks.is_empty() {
            return order;
        }
        seen[0] = true;
        while let Some((block, next)) = stack.pop() {
            match self.blocks[block].successors.get(next) {
                Some(&successor) => {
                    stack.push((block, next + 1));
                    if !seen[successor] {
                        seen[successor] = true;
                        stack.push((successor, 0));
                    }
                }
                None => order.push(block),
            }
        }
        order.reverse();
        // A block no edge reaches -- a listing that begins mid-function, a case block reached only
        // through a table -- is still a block, and dropping it would lose every case in it.
        order.extend((0..self.blocks.len()).filter(|block| !seen[*block]));
        order
    }
}

/// Builds the graph of a function's listing.
pub(crate) fn graph(listing: &[Instruction]) -> Graph {
    let index_of: HashMap<u64, usize> = listing
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.address, index))
        .collect();

    // A block starts at the function's entry, at every branch or jump target inside it, and after
    // every instruction that ends one.
    let mut starts: BTreeSet<usize> = BTreeSet::new();
    starts.insert(0);
    for (index, instruction) in listing.iter().enumerate() {
        let target = match instruction.flow {
            Flow::Branch(target) | Flow::Jmp(target) => target,
            _ => None,
        };
        if let Some(target) = target
            && let Some(&at) = index_of.get(&target)
        {
            starts.insert(at);
        }
        if ends_a_block(&instruction.flow) && index + 1 < listing.len() {
            starts.insert(index + 1);
        }
    }

    let bounds: Vec<usize> = starts.into_iter().collect();
    let mut blocks = Vec::with_capacity(bounds.len());
    for (position, &start) in bounds.iter().enumerate() {
        let end = bounds.get(position + 1).copied().unwrap_or(listing.len());
        blocks.push(Block {
            start,
            end,
            successors: Vec::new(),
        });
    }
    let block_at: HashMap<usize, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();

    let mut by_instruction = vec![0usize; listing.len()];
    for (index, block) in blocks.iter().enumerate() {
        by_instruction[block.start..block.end].fill(index);
    }

    // Computed first and assigned after, because a block's successors are read off the listing
    // while the blocks themselves are what is being filled in.
    let successors: Vec<Vec<usize>> = blocks
        .iter()
        .map(|block| {
            let mut successors = Vec::new();
            let Some(last) = block.end.checked_sub(1).and_then(|last| listing.get(last)) else {
                return successors;
            };
            let mut reach = |target: Option<u64>| {
                if let Some(target) = target
                    && let Some(&at) = index_of.get(&target)
                    && let Some(&successor) = block_at.get(&at)
                {
                    successors.push(successor);
                }
            };
            match last.flow {
                // Both successors: the branch's target, and the instruction after it.
                Flow::Branch(target) => {
                    reach(target);
                    if block.end < listing.len() {
                        successors.push(by_instruction[block.end]);
                    }
                }
                // No fall-through past an unconditional jump, and none at all past an indirect one.
                Flow::Jmp(target) => reach(target),
                // A call returns, so the block continues after it -- and the callee is not an edge
                // in *this* function's graph.
                Flow::Call(_) | Flow::Fallthrough => {
                    if block.end < listing.len() {
                        successors.push(by_instruction[block.end]);
                    }
                }
                // Nothing follows a return, a trap, or bytes that are not an instruction.
                Flow::Return | Flow::Trap | Flow::Unreadable | Flow::Unknown => {}
            }
            successors.sort_unstable();
            successors.dedup();
            successors
        })
        .collect();
    for (block, successors) in blocks.iter_mut().zip(successors) {
        block.successors = successors;
    }

    Graph {
        blocks,
        by_instruction,
    }
}

/// Whether an instruction is the last of its block.
fn ends_a_block(flow: &Flow) -> bool {
    match flow {
        Flow::Branch(_) | Flow::Jmp(_) | Flow::Return | Flow::Trap => true,
        // **An instruction nobody could read ends a block**, for the reason
        // `crate::driver::in_listing_order` puts a barrier there: joining what precedes it to
        // whatever follows invents an edge across the hole. `Unknown` is the same fact one step
        // less severe -- there is an instruction and this build did not decode it, so where it
        // goes is not known and assuming a fall-through is the invention.
        Flow::Unreadable | Flow::Unknown => true,
        // A call's block continues at the instruction after it.
        Flow::Call(_) | Flow::Fallthrough => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbgscope::dbgeng::{Effect, Operand};

    const AT: u64 = 0x1000;

    fn insn(address: u64, mnemonic: &str, flow: Flow) -> Instruction {
        Instruction {
            address,
            bytes: String::new(),
            text: String::new(),
            mnemonic: mnemonic.to_string(),
            operands: Vec::new(),
            flow,
            // None of the decoder's other answers shapes a graph, which is the point of the test
            // below that says so.
            privileged: false,
            effect: Effect::Other,
            condition: None,
            writes_flags: false,
        }
    }

    /// The blocks and the edges of an ordinary compare chain.
    ///
    /// A conditional branch has **two** successors and the listing's order says nothing about
    /// which is which, a `ret` has none, and the block after it is reached from wherever branched
    /// there rather than from the return above it. That last one is the whole reason this module
    /// exists: `uf` prints blocks in sequence, and a pass reading the listing straight through
    /// carries facts across a seam control flow never crosses.
    #[test]
    fn a_branch_has_two_successors_and_a_return_has_none() {
        let listing = vec![
            insn(AT, "cmp", Flow::Fallthrough),
            insn(AT + 2, "je", Flow::Branch(Some(AT + 8))),
            insn(AT + 4, "xor", Flow::Fallthrough),
            insn(AT + 6, "ret", Flow::Return),
            insn(AT + 8, "mov", Flow::Fallthrough),
            insn(AT + 10, "ret", Flow::Return),
        ];

        let graph = graph(&listing);

        assert_eq!(
            graph
                .blocks
                .iter()
                .map(|block| (block.start, block.end, block.successors.clone()))
                .collect::<Vec<_>>(),
            vec![(0, 2, vec![1, 2]), (2, 4, vec![]), (4, 6, vec![])],
            "{:?}",
            graph.blocks
        );
        assert_eq!(
            graph
                .blocks
                .iter()
                .enumerate()
                .filter(|(_, block)| block.successors.contains(&2))
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            vec![0],
            "reached from the branch, and not from the block above it"
        );
    }

    /// An **indirect** transfer has no successor, and neither does a target outside the listing.
    ///
    /// A guessed edge is the one thing a walk resting on this must never have: an unresolved
    /// switch that fell through to whatever the compiler printed next would put every following
    /// case block on a path that does not exist. A call is the other way round — it returns, so
    /// its block continues, and the callee is not an edge in this function's graph.
    #[test]
    fn an_indirect_transfer_and_a_departing_branch_have_no_edge() {
        let listing = vec![
            insn(AT, "call", Flow::Call(Some(0xdead))),
            insn(AT + 5, "jmp", Flow::Jmp(None)),
            insn(AT + 7, "mov", Flow::Fallthrough),
            insn(AT + 9, "jmp", Flow::Jmp(Some(0xfa11))),
            insn(AT + 11, "ret", Flow::Return),
        ];

        let graph = graph(&listing);

        assert_eq!(
            graph
                .blocks
                .iter()
                .map(|block| (block.start, block.end, block.successors.clone()))
                .collect::<Vec<_>>(),
            vec![(0, 2, vec![]), (2, 4, vec![]), (4, 5, vec![])],
            "the call's block runs to the indirect jump, which goes nowhere here: {:?}",
            graph.blocks
        );
    }

    /// An instruction that would not read ends its block and has no successor.
    ///
    /// There is no instruction there, so there is nothing after it: joining what precedes the hole
    /// to whatever follows invents an edge across it, which is the same rule
    /// `crate::driver::in_listing_order` puts a barrier in the listing for.
    #[test]
    fn a_hole_in_the_listing_ends_a_block_and_reaches_nothing() {
        let listing = vec![
            insn(AT, "mov", Flow::Fallthrough),
            insn(AT + 2, "", Flow::Unreadable),
            insn(AT + 3, "cmp", Flow::Fallthrough),
            insn(AT + 5, "ret", Flow::Return),
        ];

        let graph = graph(&listing);

        assert_eq!(
            graph
                .blocks
                .iter()
                .map(|block| (block.start, block.end, block.successors.clone()))
                .collect::<Vec<_>>(),
            vec![(0, 2, vec![]), (2, 4, vec![])],
            "{:?}",
            graph.blocks
        );
    }

    /// A block entered from two places has both as predecessors, which is what a join needs.
    #[test]
    fn a_shared_block_keeps_every_edge_into_it() {
        let listing = vec![
            insn(AT, "cmp", Flow::Fallthrough),
            insn(AT + 2, "je", Flow::Branch(Some(AT + 8))),
            insn(AT + 4, "cmp", Flow::Fallthrough),
            insn(AT + 6, "jne", Flow::Branch(Some(AT + 8))),
            insn(AT + 8, "mov", Flow::Fallthrough),
            insn(AT + 10, "ret", Flow::Return),
        ];

        let graph = graph(&listing);

        let shared = graph.holding(4).expect("the target is in a block");
        let into: Vec<usize> = graph
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, block)| block.successors.contains(&shared))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(into, vec![0, 1], "{:?}", graph.blocks);
    }

    /// The walk order visits a block after the ones that reach it, and still reaches a block that
    /// nothing does.
    ///
    /// A dispatch routine's graph has loops, so an order that required every predecessor first
    /// would refuse the function. And a block nothing reaches -- a listing that begins
    /// mid-function, a case only a jump table selects -- is still a block: dropping it would lose
    /// every case in it, which is the failure this order is arranged around rather than a tidiness
    /// question.
    #[test]
    fn the_walk_order_covers_every_block_including_the_unreachable_one() {
        let listing = vec![
            insn(AT, "cmp", Flow::Fallthrough),
            insn(AT + 2, "je", Flow::Branch(Some(AT + 6))),
            insn(AT + 4, "ret", Flow::Return),
            insn(AT + 6, "jmp", Flow::Jmp(Some(AT))),
            // Reached by nothing in this listing.
            insn(AT + 8, "mov", Flow::Fallthrough),
            insn(AT + 10, "ret", Flow::Return),
        ];

        let graph = graph(&listing);
        let order = graph.walk_order();

        assert_eq!(
            order.len(),
            graph.blocks.len(),
            "every block is visited: {order:?} against {:?}",
            graph.blocks
        );
        let position = |block: usize| order.iter().position(|&at| at == block).unwrap();
        assert!(
            position(0) < position(1),
            "and a block follows what reaches it where the graph allows: {order:?}"
        );
        let orphan = graph.holding(4).expect("the orphan is in a block");
        assert!(order.contains(&orphan), "{order:?}");
    }

    /// An operand list plays no part in the shape: the flow does.
    ///
    /// Which is what lets the analyses above it decide what an instruction *means* while this
    /// decides only where control can go -- and is why a fixture here needs no operands at all.
    #[test]
    fn the_shape_comes_from_the_flow_rather_than_the_operands() {
        let mut listing = vec![
            insn(AT, "mov", Flow::Fallthrough),
            insn(AT + 2, "ret", Flow::Return),
        ];
        let plain = graph(&listing);
        listing[0].operands = vec![Operand::Immediate(7)];
        let with_operands = graph(&listing);

        assert_eq!(plain, with_operands);
    }
}
