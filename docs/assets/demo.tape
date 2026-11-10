# The README demo. Re-record from the repository root after a release with
#   vhs docs/assets/demo.tape
# It runs this checkout's code as `aak`, so the version it prints is the checkout's.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 760
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set CursorBlink false

Hide
Type `export PS1='$ ' REPO=$PWD && aak() { PYTHONPATH=$REPO python3 -c 'from agent_audit_kit.cli import cli; cli(prog_name="aak")' "$@"; } && cd examples/vulnerable-configs/02-shell-injection && clear`
Enter
Sleep 500ms
Show

Type "aak --version"
Sleep 400ms
Enter
Sleep 1.5s

Type "aak scan . --severity critical"
Sleep 400ms
Enter
Sleep 7s

Type "aak score ."
Sleep 400ms
Enter
Sleep 3s
