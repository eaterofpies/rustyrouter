---
name: commit-helper
description: Guidelines and instructions for running git commits securely and obtaining approval for git commit commands when the environment cancels context or denies permissions.
---

# Git Commit Helper Skill

This skill provides the instructions for performing git commits securely and resolving git command permission errors.

## 1. Commit Guidelines
* Always run a clean compilation check (`cargo check`) and unit tests (`cargo test`) before committing.
* STRICT RULE: Never execute a git commit command without asking and obtaining explicit approval from the USER in the chat first.
* Format commit messages using Conventional Commits:
  * `feat: ...` for new features.
  * `fix: ...` for bug fixes.
  * `refactor: ...` for code cleanup.
  * `test: ...` for test suites.

## 2. Resolving Permission / Context Cancellation Errors
If a command like `git commit` fails with `permission check failed` or `context canceled`, it means the terminal sandbox or authorization layer blocked the command prefix. To resolve this:
1. Invoke the `ask_permission` tool to request permission for the `git` command scope:
   * **Action**: `command`
   * **Target**: `git`
   * **Reason**: `Allow git stage, commit, and status commands to run`
2. Once the permission is approved, execute the commit command again.
