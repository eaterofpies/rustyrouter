---
name: rust-guidelines
description: Coding standards and guidelines for writing clean, flat, and idiomatic Rust code in this project, including package constants, no magic numbers, flat nesting, and small functions.
---

# Rust Coding Guidelines Skill

This skill provides code style and design standards for writing and modifying Rust code in the `rustyrouter` repository.

## 1. Package Constants
* Avoid redefining protocol or system constants.
* Always import and use official constants from packages/crates (e.g., `dhcproto::v4::SERVER_PORT`, `dhcproto::v4::CLIENT_PORT`, `std::net::Ipv4Addr::BROADCAST`, `std::net::Ipv4Addr::UNSPECIFIED`).

## 2. Leverage Crates/Packages
* Prefer using existing library solutions over rolling custom implementations (e.g., using `ipnet` for parsing IP nets and calculating host scopes instead of bit-shifting IP octets).

## 3. No Magic Numbers
* Do not use raw literals for port numbers, offsets, flags, or configuration defaults.
* Declare `const` values at the module level or import them from standard libraries / external crates.

## 4. Indentation & Indentation Layer Limits
* **Strict nesting limit**: Indentation must be kept flat (ideally a maximum of 2 layers).
* Eliminate arbitrary nested scope blocks.
* Refactor deep matching blocks, socket read/write setups, and complex state changes by extracting them into dedicated, flat functions.

## 5. Small, Single-Purpose Functions
* Write small, highly focused functions that perform a single task.
* Deconstruct long event loops into simple sequential function calls.

## 6. Strict Error Handling
* **Never discard or swallow errors silently** (e.g. using `let _ = ...` or empty `catch`/`unwrap_or` blocks).
* **Avoid unconditional `unwrap()` or `expect()` calls** in production code, as they trigger abrupt panics. Prefer bubbling up errors using `Result` or `Option` mapping.
* **Wrap errors in custom error types** (e.g., custom error enums or `thiserror`-like types) where appropriate. This aids calling code with precise identification, categorization, and domain-specific error handling.
* Critical initialization and configuration errors (such as network interface configuration, packet parsing, or file mounting failures) must cause program failure or transition to a safe panic recovery reboot state rather than continuing in an undefined/broken state.
