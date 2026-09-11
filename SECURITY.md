# Security

## The bridge has no authentication, by design

The HTTP server binds to `127.0.0.1` and has **no authentication and no
authorisation**. Anyone who can reach the port can read every program Ghidra has
open, and — because the bridge exposes renaming, retyping, comment and memory
patching endpoints — can modify them.

That is an acceptable trade-off for a loopback-only developer tool, and it is why:

* the default bind address is `127.0.0.1`, and
* `Allow Remote Connections` must be enabled explicitly before the server will
  bind a non-loopback interface.

**Do not enable remote binding on a machine you do not fully control, and never
expose the port to the internet.** If you need remote access, tunnel it over SSH
rather than binding a routable interface:

```sh
ssh -L 8192:127.0.0.1:8192 user@your-analysis-host
```

## Script execution

`POST /scripts/execute` runs arbitrary code inside the Ghidra JVM, including
inline Java/Python source supplied in the request. That is intentional — it is the
escape hatch for analysis with no dedicated endpoint — but it means an agent with
access to the bridge can execute code with your privileges.

Host-side switch: `ApiContext.setScriptExecutionAllowed(false)` disables it. There
is currently no tool option wired to that switch; if you need it, say so in an
issue.

## Reporting a vulnerability

Open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
rather than a public issue, or contact the maintainer directly.

Please include:

* what an attacker can achieve, and the preconditions (is the bridge already
  reachable? is remote binding on?)
* the exact request that demonstrates it
* the Ghidra version

There is a genuine class of bugs worth looking for here: endpoints that let a
request escape the loopback trust boundary, or that turn a read-only request into
a mutation. Both are in scope.

## Supported versions

Only the latest released version is supported. The bridge targets Ghidra 12.1.3;
issues that only reproduce on other Ghidra versions are unlikely to be fixed.
