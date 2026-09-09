#!/usr/bin/env bash
# Install the VAPT recon copilot into a VS Code workspace.
#
# Copies two things that have to travel together:
#   .github/   Copilot instructions, chat mode and prompt files
#   scripts/   the tested js-recon analysis scripts the prompts call
#
# The scripts are copied from the js-recon skill rather than duplicated in this
# directory, so there is one source of truth and no drift between the Claude and
# Copilot packages. That is also why this installer exists at all: when the two
# halves are copied separately it is easy to bring the prompts without the
# scripts, and Copilot then rewrites them from scratch -- untested, and
# differently each run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
SRC_SCRIPTS="$REPO/.claude/skills/js-recon/scripts"

usage() {
  cat <<USAGE
Usage: $(basename "$0") <workspace-dir> [--force] [--verify]

  <workspace-dir>  Folder you open in VS Code -- normally where the engagement's
                   saved bundles and Burp exports live.
  --force          Overwrite existing .github/ and scripts/ without asking.
  --verify         Run the js-recon smoke test after installing.

Example:
  $(basename "$0") ~/engagements/acme-webapp --verify
USAGE
}

TARGET=""; FORCE=0; VERIFY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --force)  FORCE=1 ;;
    --verify) VERIFY=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)  if [ -n "$TARGET" ]; then echo "Only one workspace dir expected." >&2; exit 2; fi
        TARGET="$1" ;;
  esac
  shift
done

[ -n "$TARGET" ] || { usage >&2; exit 2; }

if [ ! -d "$TARGET" ]; then
  echo "Workspace directory does not exist: $TARGET" >&2
  echo "Create it first, or point at the folder you open in VS Code." >&2
  exit 1
fi
TARGET="$(cd "$TARGET" && pwd)"

if [ ! -d "$SRC_SCRIPTS" ]; then
  echo "Cannot find the js-recon scripts at:" >&2
  echo "  $SRC_SCRIPTS" >&2
  echo "Run this from a full checkout of the repository -- the installer copies" >&2
  echo "the scripts from the skill rather than keeping a second copy." >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  echo "Warning: python3 not found on PATH. The scripts are stdlib-only Python 3;" >&2
  echo "install Python 3 or the prompts will fall back to generating code." >&2
}

confirm_overwrite() {  # confirm_overwrite <path>
  [ -e "$1" ] || return 0
  [ "$FORCE" -eq 0 ] || return 0
  printf 'Overwrite existing %s? [y/N] ' "$1"
  read -r reply </dev/tty || reply=""
  case "$reply" in [yY]*) return 0 ;; *) echo "Aborted."; exit 1 ;; esac
}

confirm_overwrite "$TARGET/.github"
confirm_overwrite "$TARGET/scripts"

mkdir -p "$TARGET/.github" "$TARGET/scripts"
cp -R "$HERE/.github/." "$TARGET/.github/"
cp -R "$SRC_SCRIPTS/." "$TARGET/scripts/"
chmod +x "$TARGET/scripts/"*.py 2>/dev/null || true

echo "Installed into $TARGET"
echo "  .github/copilot-instructions.md"
echo "  .github/chatmodes/    $(ls -1 "$TARGET/.github/chatmodes" | wc -l | tr -d ' ') chat mode"
echo "  .github/instructions/ $(ls -1 "$TARGET/.github/instructions" | wc -l | tr -d ' ') scoped instruction file"
echo "  .github/prompts/      $(ls -1 "$TARGET/.github/prompts" | wc -l | tr -d ' ') slash commands"
echo "  scripts/              $(ls -1 "$TARGET/scripts"/*.py | wc -l | tr -d ' ') analysis scripts"

if [ "$VERIFY" -eq 1 ]; then
  echo
  echo "Verifying the scripts run correctly..."
  if [ -f "$REPO/.claude/skills/js-recon/tests/smoke_test.sh" ]; then
    bash "$REPO/.claude/skills/js-recon/tests/smoke_test.sh" | tail -3
  else
    echo "  Smoke test not found; running a syntax check instead."
    for f in "$TARGET/scripts"/*.py; do python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f"; done
    echo "  All scripts parse."
  fi
fi

cat <<NEXT

Next:
  1. Open $TARGET in VS Code.
  2. Pick the "VAPT Recon" chat mode in Copilot Chat.
  3. Drop your Burp XML export and any saved bundles into the workspace.
  4. Run /js-endpoints -- it will call scripts/parse_burp.py rather than
     writing its own parser.

If Copilot still writes its own analysis code, it could not see scripts/.
Check that the folder opened in VS Code is $TARGET and not a parent or
subfolder of it.
NEXT
