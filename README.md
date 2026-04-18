# GenLayer Adversarial Testing

Adversarial testing scenarios, attack simulations, and edge case explorations for GenLayer Intelligent Contracts. This repo documents real attack vectors, shows vulnerable versus hardened contract examples, and provides recommendations for improving contract security.

---

## What is in this repo

ADVERSARIAL_TESTING.md contains the full testing document covering five attack scenarios with vulnerable and hardened contract examples, five edge cases that expose unexpected behavior, and a findings section with recommendations organized by severity.

## Why I wrote this

After building several Intelligent Contracts for the GenLayer hackathon I started thinking about what could go wrong if someone actually tried to exploit them. GenLayer contracts are different from traditional smart contracts because they interact with AI models and live web data, which means the attack surface is different too. This document is my attempt to think through the main threats systematically and show what the fixes look like in actual code.

## Attack scenarios covered

The first scenario covers prompt injection, where malicious user input tries to override the contract logic by embedding instructions inside the data. The second covers consensus manipulation through tolerance abuse, where an attacker exploits the allowed variance in the Equivalence Principle. The third covers data source poisoning, where an attacker serves manipulated content from a URL they control. The fourth covers the validator disagreement exploit, where a weak validator function that always returns True defeats the entire consensus mechanism. The fifth covers storage overflow attacks through repeated writes to unbounded arrays.

## Edge cases covered

Empty input handling, very long input beyond expected limits, special characters and unicode that could break JSON parsing, concurrent resolution attempts before finalization, and URL redirects that could bypass domain validation.

## Main findings

The highest risk is prompt injection for any contract that accepts user text. The fix is input sanitization combined with clear prompt delimiters. The second most critical issue is validator functions that always return True, which completely undermines Optimistic Democracy. The validator must always re-run the leader function independently and compare results. User-controlled URLs in oracle contracts should be restricted to a trusted domain allowlist.

## How to use this

Read ADVERSARIAL_TESTING.md for the full scenarios and code examples. The hardened contract patterns in the document can be copied directly into GenLayer Studio. The findings section provides a prioritized list of what to fix first when securing an Intelligent Contract.

Note: the contract in this repository uses the Address type in the constructor as required by genvm-lint. When deploying in GenLayer Studio use a version that receives str in the constructor and converts internally with Address(owner_address) since Studio requires primitive types to parse the contract schema correctly.

## Resources

GenLayer Greyboxing Documentation: https://docs.genlayer.com/_temp/security-and-best-practices/grey-boxing

GenLayer Prompt Injection Guide: https://docs.genlayer.com/developers/intelligent-contracts/security-and-best-practices/prompt-injection

GenLayer Studio: https://studio.genlayer.com
