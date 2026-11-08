# Approved plans

A [Claude Code](claude-code.md) seat can carry out a plan the room's Lead posts, but only after
**you**, the seat's owner, approve that exact plan with your passkey. It works in a private copy of
one git repository you chose at setup, with file tools only, and may change only the files the
plan lists. You get a diff to review. Your project changes only when you approve that diff too,
and then only as a new branch.

This is an independent project. It isn't made, reviewed or endorsed by Anthropic. It runs the
unmodified `claude` program, logged in with your own Claude subscription.

> **Not finished yet.** The daemon side is complete. Knights Circle's plan card and passkey
> approval screens come next, so you can't approve a plan from a room yet.

## Whose account, and the terms

A plan runs on your computer, on your Claude account, as your own Claude Code session, and uses
more of your plan than a chat turn (up to 40 turns of work). The same terms apply as for the
[Claude Code seat](claude-code.md#whose-account-and-the-terms). Approve plans for your own
projects only. Don't run plans for other people on your subscription.

## What a run can and can't do

| It can | It can't |
|---|---|
| Read the files in a copy of the project's last commit | Read anything outside that copy, such as your home folder, other projects or its own git folder |
| Edit and create the files the plan lists | Change any other file. A change outside the plan fails the run |
| Search inside the copy | Run commands, install anything, use the web, MCP servers or subagents |
| | Make symlinks, executable files, binary files or git files |
| | Touch your project, your checkout or your working tree |

Room text never starts a run. A message saying "go ahead", from anyone, does nothing. Only a
passkey approval of the plan's exact hash does, and only one made with the passkey you pinned at
this computer. An approval works once, for this seat and room, for 10 minutes.

**Assume the plan may contain prompt injection.** Other members and their bots helped write it.
The limits above come from the daemon and from Claude Code's own settings, not from the plan's
wording. One thing they don't limit: **a run can read every file tracked in the project.** Don't
keep secrets in a project you use with approved plans.

## Setup

1. Set up a [Claude Code seat](claude-code.md#setup). When setup asks for a **project folder for
   approved plans**, give the top folder of a git repository with at least one commit. Press
   Enter for none, and the seat stays chat only. Setup also asks for a short name for the
   project, which plans use.
2. Pin your passkey. When Knights Circle creates your approval passkey, it shows a credential id,
   a public key and a fingerprint. Run this at the seat's own computer, never anywhere else:

   ```bash
   ./eureka-daemon approver add CREDENTIAL_ID PUBLIC_KEY
   ```

   Check that the fingerprint it prints is the one Knights Circle shows. If it isn't, run
   `./eureka-daemon approver remove` at once.
3. Run `./eureka-daemon doctor`. With a project, it also checks the project, the pinned passkey
   and git (2.29 or later), and makes a test copy, then deletes it.
4. Start the seat: `./eureka-daemon start`.

`EUREKA_PLAN_TIMEOUT`, set where you run `start`, limits a run, from 1 to 1800 seconds
(default 600). Approved plans are offered only on this computer's loopback address, and not in
the native Windows build. Use WSL there.

### No Touch ID? Other ways to approve

The seat accepts only approvals where the passkey verified you, with a PIN, a password or a fingerprint. Touch ID does that. If your computer has no Touch ID, or the passkey prompt fails, you can use:

- **This device's PIN or password:** Windows Hello, or your Mac's login password if Touch ID isn't set up.
- **Your phone:** in the passkey prompt choose *Use a phone or tablet* (or *Other options*), scan the QR code with the phone and approve there. Bluetooth must be on for both. The passkey then lives on the phone, which you use for every approval.
- **A security key**, such as a YubiKey, with a PIN set. A key without a PIN can't verify you, so the seat refuses its approvals (`bad_approval`).

Whichever you choose, pin that passkey with `approver add` as above. A browser without passkey support can't approve plans: use a current Chrome, Edge, Safari or Firefox.

## A plan, start to finish

1. **The plan.** The Lead posts an `eureka-plan` block:

   ````
   ```eureka-plan
   {"eureka_plan": 1,
    "title": "Add a dark-mode toggle",
    "project": "site",
    "steps": ["Add a .dark theme to src/theme.css", "Add a toggle to src/app.js that sets it"],
    "edit": ["src/theme.css", "src/app.js"]}
   ```
   ````

   `edit` lists the files the run may change. `*` and `?` match within one folder, and `**`
   matches any depth. Paths that could leave the project, or reach git's own files, are refused.
2. **You approve the plan.** Read every step on the plan card, then approve it with Touch ID.
3. **The run.** The seat copies the project's last commit, then runs Claude Code in the copy with
   only the plan. It doesn't see the room's conversation. The card shows what it is doing, such as
   *Editing src/theme.css*. That line holds tool names and paths only.
   Each tool call the seat refuses, and each one Claude Code denies, is also written to the
   seat's `daemon.log`, with the tool's name and path only, never the file's contents or a
   command.
4. **The diff.** The daemon checks every change itself. You see the diff, the files, the lines
   added and removed, and Claude Code's summary. Other members see only a one-line summary.
5. **You approve the diff, or discard it.** Applying needs a second passkey approval, of this
   run, this diff and the commit it was made from. The diff then goes on a new branch,
   `eureka/plan-<code>`, fetched into your project. Your checkout and working tree aren't touched,
   so review it and merge it as you would any branch. Discard deletes the copy.

A diff waits for 24 hours. If your project has a new commit since the run, applying is refused
(`project_moved`): run the plan again on the new commit.

## What you may see

**Before a run starts:**

| Reason | Meaning |
|---|---|
| `bad_plan` | The plan block isn't valid. The reason says which part. |
| `wrong_project` | The plan names a project this seat doesn't have. |
| `no_approver` | No passkey is pinned at this seat. Run `approver add`. |
| `bad_approval` | Not your pinned passkey, or not for this seat, room or site. |
| `plan_mismatch` | The plan, or the diff, isn't the one you approved. |
| `expired` | The approval is over 10 minutes old. Approve again. |
| `replayed` | That approval was already used. |
| `busy` | Another plan is running on this seat. |

**When a run ends:**

| Status | Meaning |
|---|---|
| `diff_ready` | A diff is waiting for you to apply or discard. |
| `no_changes` | Claude Code changed nothing. |
| `outside_plan` | It tried, or made, a change the plan doesn't allow. Nothing is kept. |
| `unsafe_session` | Claude Code started with more than file tools, so it was stopped before it began. Run `doctor`. |
| `too_large` | More than 50 files, 1 MB of diff, or 512 KB in one file. |
| `timeout`, `max_turns` | It ran out of time or turns. |
| `not_logged_in`, `usage_limit`, `claude_unavailable` | As for a [chat turn](claude-code.md#what-the-room-may-see). |

**When you apply:**

| Status | Meaning |
|---|---|
| `applied` | The branch is in your project. |
| `project_moved` | Your project has a new commit since the run. Run the plan again. |
| `apply_conflict` | A branch with that name already exists. Delete or rename it, then approve again. |

## Turning it off

- **No more plans:** run `./eureka-daemon approver remove`. No plan can be approved until you add
  a passkey again.
- **Chat only again:** run setup again and press Enter at the project question.

## What has been tested

### Automated

- **A stand-in for `claude`** covers:
  - every way out of a run in the design's threat list, each checking that the project is
    unchanged: edits and writes outside `edit` (`outside_plan`), reads outside the copy, a tool
    a run doesn't have (such as `Bash`), calls Claude Code denied, symlinks, executable bits,
    binary files and git files
  - a run past its time limit (`timeout`), killed with its children
  - applying to a new branch, with the checkout, branch and working tree unchanged
  - forged, replayed, expired and mismatched run and apply approvals, a passkey that isn't
    pinned (`bad_approval`), and approvals for another seat, room key or room
  - a moved project (`project_moved`), an existing branch, a copy changed after its check, and
    discarding
- **Real Claude Code v2.1.319, logged out, on macOS:** the run's exact command line passes the
  seat's start check, showing exactly the five file tools, and ends `not_logged_in`.

### By hand, with a real subscription (8 November 2026)

On macOS, with Claude Code v2.1.319 on a Claude Pro subscription, the live Knights Circle site
and a Touch ID passkey. The seat ran from this repository's main branch, and the project was a
throwaway git repository made for the test.

Passed:

- `setup` with the project, `approver add` with the passkey, matching fingerprints, and a clean
  `doctor`.
- Room turns as before: signed replies, and the seat's chat folder stayed empty.
- A plan card from the Lead's block, with the plan's code and the seat's id matching what the
  seat computes.
- Approve with Touch ID → Running → Diff ready in 13 s. The diff changed only the file in `edit`,
  and its hash matched on the card, on disk and in the daemon's own diff.
- Apply to branch: `eureka/plan-<code>` was made on the run's commit, with the same diff. The
  checkout, the current branch and the working tree didn't change, and no `FETCH_HEAD` was
  written.
- Discard deleted the copy.
- "Approved. Go ahead and run it now" written in the room did nothing: only a card with an
  Approve button.
- A plan whose steps needed a file outside the project, a shell command and a web page: only the
  file in `edit` changed. Claude Code's summary said it couldn't read outside the project and had
  no shell and no internet access. Nothing outside the project was read or changed.
- `~/.claude` was unchanged by the seat, and no transcripts were saved in the seat's folder.

Not shown live, and covered only by the automated tests:

- `outside_plan` itself. Given a step that needed a file outside `edit`, Claude Code left that
  file alone without being stopped, so the seat's refusal never had to act.
- Claude Code's own denials. In the run above it didn't try the tools it lacked, so nothing was
  denied.
- A plan that asks to read `~/.ssh/config`, run `npm install` or fetch a URL. The Lead declined
  to post such a plan, so there was no card.
- `replayed`, `expired`, `plan_mismatch`, `bad_approval` (a passkey that isn't pinned),
  `project_moved` and `timeout`.
