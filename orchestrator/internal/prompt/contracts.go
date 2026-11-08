// SPDX-License-Identifier: Apache-2.0

package prompt

// The built-in contracts every prompt carries, after the task and its register context, unless
// the site's configuration replaces them (prompt_contracts) or adds to them
// (prompt_contracts_append). They name the output tools this repository defines: finding_write
// and proposal_file, which the broker's MCP server (hnx-broker) serves, through which an agent
// records what it found or asks for a change (ADR-0030: agents act only through the broker).

// evidenceContract asks for the exact query behind every claim a decision could rest on, so a
// reviewer can re-run it instead of reconstructing it.
const evidenceContract = `[evidence-appendix] For every specific number, count, rate or "no evidence of X" claim in your output that a decision could rest on, add it to an "## Evidence Appendix" section with the exact query, command or tool call you ran (verbatim, not reconstructed from memory) and its raw result. A reviewer must be able to re-run your cited query and get your answer. When a claim is an inference, an assumption or general knowledge rather than something you measured, say so plainly instead of presenting it as measured.`

// loopContract stops a run that has started repeating itself: a degrading context re-derives the
// same conclusion instead of finishing.
const loopContract = `[loop-detection] If you notice yourself repeating a conclusion, re-reading the same instruction, or re-deriving an analysis you already completed earlier in this turn, that is a sign of context degradation, not a reason to check again. Stop at once: call your output tool with what you have already concluded, or end your turn stating plainly that you did not finish and why.`

// outputToolContract makes the deliverable the tool call, not the chat answer: the controller reads
// what a run recorded, never its final message.
const outputToolContract = `[required-tool-call] Your task is complete only when you have called your output tool with your result: finding_write for a finding, proposal_file for a proposed change (both through the broker), or the output tool your profile grants instead. A thorough final message that never calls that tool is a failed run, the same as no output at all: nothing reads your chat response, only what you recorded through the tool. Before you end your turn, check that you called it this turn with your real conclusion; if not, call it now, even if you already wrote the same content as prose.`

// DefaultContracts returns the built-in contracts, in prompt order: the evidence appendix, loop
// detection and the required output tool call. A new slice each call.
func DefaultContracts() []string {
	return []string{evidenceContract, loopContract, outputToolContract}
}
