# Codex CLI chat seat

The Rust daemon starts a fresh Codex conversation for each signed Knights Circle room turn. Use a macOS or Linux HTTPS build. The minimum and only validated CLI is **0.166.0-alpha.5.1**. Doctor and startup refuse unknown, older and newer versions. Set `EUREKA_CODEX_BIN` to the exact executable before setup if it is outside PATH.

Each room turn and doctor wake has a **120-second** limit. The daemon points the pinned CLI at a single-use loopback Responses endpoint. Before contacting ChatGPT, the endpoint checks the actual request for advertised tools. The pinned CLI can omit the tools field for an empty inventory. The guard accepts that form only for a recognized standalone request, rejects populated or malformed inventories and forwards an explicit empty list with tool choice set to none. Each turn needs a successful guard check and a completed CLI assistant event. Unexpected tool events fail the turn.

The daemon reads the **seat's file-based ChatGPT login** after checking the request and sends its access token over HTTPS to the fixed ChatGPT Responses endpoint. The transcript goes to ChatGPT and uses the signed-in account's plan. Tool execution and project approvals are outside this seat's scope.

## Mac acceptance checklist (operator test, still pending)

- [ ] From Terminal, build the draft with `cargo build --release --locked --manifest-path rust/Cargo.toml`. From the repo root, set `daemon="$PWD/rust/target/release/eureka-daemon"` and `seat="$HOME/.eureka/codex-review"`. Choose a new, private seat directory. Set `EUREKA_CODEX_BIN` if needed.
- [ ] Quit other Codex sessions for a clean baseline, including the desktop app. Save a read-only inventory before setup. The commands below capture content hashes, symlink targets and filesystem metadata under your personal Codex directory locally. Keep the temporary output private.

  ```sh
  audit=$(mktemp -d)
  snapshot() {
    (cd "$HOME" && if test -d .codex; then
      find .codex -exec stat -f '%N %p %m %c' {} + | LC_ALL=C sort
      find .codex -type f -exec shasum -a 256 {} + | LC_ALL=C sort
      find .codex -type l -exec ls -ld {} + | LC_ALL=C sort
    fi)
  }
  snapshot > "$audit/before"
  ```

- [ ] In Knights Circle, open **Advanced: bring your own bot → Show room key**. Run `"$daemon" setup --dir "$seat"`, choose **6. Codex CLI**, pick an unused port and enter the room's public key. Keep the name, host and public key printed by setup.
- [ ] Complete the browser sign-in yourself from this command. Select ChatGPT login and keep the credentials in the seat folder.

  ```sh
  env HOME="$seat/codex" CODEX_HOME="$seat/codex/auth" \
    "${EUREKA_CODEX_BIN:-codex}" -c 'cli_auth_credentials_store="file"' login
  ```

- [ ] Run `"$daemon" start --dir "$seat"`, then `"$daemon" doctor --dir "$seat" --wake`. Require a successful exit and “Codex answered a live test turn with an empty tool list.”
- [ ] Add the printed seat under **External agents**, choose **Check**, then add it to a full Knights Circle room with the intended other participants. Send an ordinary question with a distinctive word. Verify the Codex seat replies in context and the other participants can continue.
- [ ] Address **“run ls ~”** to the Codex seat. Require a refusal in words. A shell listing, invented output, timed-out turn or generic transport failure fails this check. Follow up with an ordinary question to verify the seat still answers.
- [ ] Run `"$daemon" stop --dir "$seat"`. Run `snapshot > "$audit/after"`, then `diff -u "$audit/before" "$audit/after"`. Require exit zero, empty diff and no snapshot read errors. If another process changed the directory, repeat with it closed.
- [ ] Record the draft commit, CLI version, macOS version, doctor outcome, room outcome, refusal and comparison result. Keep tokens, keys, private paths and transcripts out of the PR.
