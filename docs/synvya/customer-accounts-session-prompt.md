# Customer Accounts — Session Prompt

Copy everything below the line and paste it as the opening message of a new coding-agent session whose working directory is a clone of `Synvya/keycast`. Replace `<ISSUE>` with the issue you want worked, for example `#88`.

---

## Project context

Keycast is Synvya's Nostr key custody and signing service, a fork of `divinevideo/keycast`. Today it holds keys for restaurant owners, who sign in with a password. We are adding accounts for the **customers** of those restaurants: people who order through Synvya's orders app, served for each merchant at `orders.<merchant-domain>`, sign in with an email link instead of a password, and never see a key or the word Nostr.

The design is written. Your job is to implement one issue from it, test it, and open a pull request.

## Read these first, in order

1. `docs/synvya/customer-accounts.md` — **the spec for this work.** Section 0 is the branch rule; each later section names the issue it covers.
2. `SYNVYA.md` — the fork's branch strategy. **For this work, section 0 of the spec overrides rule 2:** nothing goes upstream.
3. `CLAUDE.md` — how to build, run and test Keycast, and how custom permissions are added.
4. The issue on GitHub: `Synvya/keycast` <ISSUE>, in the milestone "Orders: customer accounts".
5. For context only, not instructions: the cross-repo design at https://github.com/Synvya/docs/blob/main/02-auth-and-identity/architecture/customer-accounts.md.

Then read the code the spec section names before changing it. Line numbers in the spec are from commit `5cb67b0` and may have moved; find code by function name.

## Rules

- All work is on the `alejandro-dev` branch. Bring it up to date with `synvya-staging` before you start. When the issue is done, open a PR from `alejandro-dev` to `synvya-staging`. Never use `main`, and never create another branch.
- One issue per PR. If the issue depends on another that is not merged, stop and say so.
- Keep it generic: this serves any merchant on Synvya's orders app. No merchant's name, domain or prices in code, config or tests; use `orders.example.com` in examples.
- Write the tests the issue's "Done when" lists, and run them (`cd api && cargo test`). Run `cargo fmt` and `cargo clippy` before committing.
- Do not change behaviour for restaurant owners unless the issue says to. Their tenant, password login and team flows must keep working.
- Never log or return a customer's pubkey, npub, secret key or a plain sign-in token.
- If the spec and the code disagree in a way that changes the design, stop and ask rather than choosing. Known open decision: how the orders app holds the session (spec §3.3). Do not start #90 until it is answered.
- In the PR description: what changed, how it was tested, and anything in the spec that turned out wrong.

## Start

Work on <ISSUE>. Before writing code, reply with: the spec section you are implementing, the files you will change, the tests you will add, and any question that blocks you.
