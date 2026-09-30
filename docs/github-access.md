# Authenticated access to this repository

Cloning and pushing from a managed machine, where a GPO or a TLS-inspecting
proxy gets in the way. Written for the case that came up here: being able to
download a ZIP from github.com but not `git clone`.

Pick **one** of the first two methods. Both end with credentials handled by the
OS keychain rather than typed each time.

## Method 1 — HTTPS with a fine-grained token (recommended on Windows)

HTTPS over 443 is the path most likely to survive a corporate firewall, and Git
for Windows ships Git Credential Manager, so the token is stored in Windows
Credential Manager rather than on disk.

1. Create a **fine-grained** personal access token at
   `github.com/settings/personal-access-tokens`. Scope it deliberately:
   - Resource owner: the account or org that owns the repository
   - Repository access: **only this repository**
   - Permissions: `Contents: Read and write`. Add `Pull requests: Read and write`
     only if you will open PRs from the CLI.
   - Expiry: the shortest that covers the engagement.

   A classic token with blanket `repo` scope grants write access to *every*
   repository you can reach. Do not use one here.

2. Clone. Git Credential Manager prompts once and stores the result:

   ```
   git clone https://github.com/eunoia-c/testrepo.git
   ```

   Username is your GitHub username; **password is the token**, not your account
   password.

3. Confirm it was stored, and not written into the remote URL:

   ```
   git remote -v
   ```

   If the output contains your token, remove it — a URL-embedded token leaks
   into `.git/config`, shell history and any log that records the remote:

   ```
   git remote set-url origin https://github.com/eunoia-c/testrepo.git
   ```

## Method 2 — SSH over port 443

Use this if HTTPS is blocked but you can reach `ssh.github.com`. Corporate
firewalls commonly block port 22 while leaving 443 open, and GitHub serves SSH
on 443 for exactly this reason.

```bash
ssh-keygen -t ed25519 -C "you@example.com"
```

Add the public key at `github.com/settings/keys`, then force SSH over 443 in
`~/.ssh/config` (`C:\Users\<you>\.ssh\config` on Windows):

```
Host github.com
  HostName ssh.github.com
  Port 443
  User git
```

Verify, then clone:

```bash
ssh -T git@github.com          # expect: "Hi <user>! You've successfully authenticated"
git clone git@github.com:eunoia-c/testrepo.git
```

## Behind a proxy

If the network requires an outbound proxy:

```bash
git config --global http.proxy http://proxy.corp.example:8080
```

## TLS interception — the one thing not to do

A TLS-inspecting proxy re-signs traffic with a corporate CA, and Git rejects it:

```
SSL certificate problem: unable to get local issuer certificate
```

The fix is to trust the corporate CA, **not** to stop verifying certificates:

```bash
git config --global http.sslCAInfo /path/to/corporate-ca-bundle.crt
```

On Windows, Git can use the OS certificate store, which already has the CA your
machine was enrolled with:

```
git config --global http.sslBackend schannel
```

Do not set `http.sslVerify=false`. It disables certificate validation for every
host you clone from, which on a security team's machine is a worse exposure than
the inconvenience it removes. If neither option above works, the CA bundle path
is wrong — ask whoever manages the proxy for it.

## If policy blocks git entirely

You can still work from a ZIP. **This repository is private**, so the plain
`archive/refs/heads/<branch>.zip` URL only works from a browser already signed in
with access; unauthenticated it returns 404, not an auth prompt. Non-interactively:

```bash
curl -L -H "Authorization: Bearer $GITHUB_TOKEN" \
  -o repo.zip \
  https://api.github.com/repos/<owner>/<repo>/zipball/<branch>
```

You lose history and the ability to push, so treat it as read-only. Note that
`copilot-vapt/` is designed to be usable from a ZIP on its own.

## This repository is private

Deliberately — it holds security tooling, a target-specific wordlist and
engagement notes. Three consequences worth knowing:

**Secret-scanning push protection may no longer apply.** GitHub provides secret
scanning and push protection free on *public* repositories; on private ones it
requires GitHub Secret Protection (previously bundled with Advanced Security),
which is a paid add-on. That protection is not cosmetic here — it blocked a push
during this repository's own history when a test fixture contained a
provider-format API key. Check Settings → Code security after changing
visibility, and if push protection is off, compensate:

- Run the repository's own secret scanner before committing:
  `python3 copilot-vapt/scripts/find_secrets.py . --min-tier probable`
- Keep the existing convention of assembling fixture credentials from fragments
  at run time (`salesforce/apex-scan/` and `servicenow/snowpick/` both do this)
  rather than storing anything provider-shaped.

**Going private does not retract what was already public.** Clones, forks and
caches made while the repository was public still exist, and search engines and
code-search services may have indexed it. Anything committed before the change
should be treated as disclosed. If any of it was genuinely sensitive — a real
credential, a client-identifying hostname — rotate or remove it at the source
rather than relying on the visibility change.

**Everyone who needs it now needs explicit access.** Add collaborators under
Settings → Collaborators, or grant a team if the repository moves to an
organisation. Tokens must be scoped to include it, and CI or automation using an
anonymous clone will start failing.

Where this session's own GitHub access is the problem instead — a clone, read or
push failing from inside Claude Code — reconnect the account at
`claude.ai/connect-github` and make sure the Claude GitHub App is installed on
the repository. A session's repositories are selected when it starts, so a
repository that cannot be attached needs a new session with it selected.

## Repository controls worth considering

Not authentication, but adjacent, and neither is set on this repository today:

- **Branch protection** on the default branch — require a pull request, and
  require the test suites to pass. Configured under Settings → Branches.
- **`CODEOWNERS`** if more than one person will review changes.

Say the word if you want any of those set up; they need repository-settings
access rather than code changes.
