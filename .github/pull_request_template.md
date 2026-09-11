<!--
Thanks for contributing. Keep the sections that apply and delete the rest.
-->

## What changed

<!-- One or two sentences. What problem does this solve? -->

## Why

<!--
The reasoning matters more than the diff. If this fixes a Ghidra quirk, say
which one — that knowledge is the expensive part to rediscover.
-->

## How it was verified

<!-- Tick what you ran. See CONTRIBUTING.md for what each one covers. -->

- [ ] `tools\build.ps1` — compiles clean (warnings are errors)
- [ ] `tools\test-json.ps1` — JSON layer unit tests
- [ ] `tools\e2e.ps1` — full endpoint sweep against a real Ghidra session
- [ ] `tests\mcp_client_test.py` — MCP protocol and tool surface
- [ ] Manual check in the Ghidra GUI (plugin loads, options behave)
- [ ] Not run — explain below

## Checklist

- [ ] New endpoints are covered by `tools/test_endpoints.ps1`
- [ ] New endpoints go through `ApiContext.read`/`mutate` (locking, transactions, EDT)
- [ ] Error messages are written for an agent to act on
- [ ] No new third-party dependency in the extension
- [ ] Docs updated if behaviour or setup changed

## Notes for the reviewer

<!-- Anything you were unsure about, or deliberately left out of scope. -->
