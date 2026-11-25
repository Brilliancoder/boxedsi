# The demo GIF of the README. Run from the repository root: vhs scripts/demo/demo.tape (see scripts/demo/README.md).
# Everything on screen is a real run on a made-up home folder written by make_home.py: no real path, key or name.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 20
Set LineHeight 1.0
Set Width 1388
Set Height 1040
Set Padding 28
Set Margin 0
Set WindowBar ""
Set CursorBlink false
Set TypingSpeed 35ms
Set Framerate 12
Set PlaybackSpeed 1.0
Set Theme { "name": "boxed-paper", "background": "#F3EFE6", "foreground": "#141414", "cursor": "#C8321A", "selection": "#E2DACB", "black": "#141414", "red": "#C8321A", "green": "#3E6B3A", "yellow": "#8A6A1F", "blue": "#2D4F7C", "magenta": "#7A3B69", "cyan": "#2F6B6B", "white": "#6B665D", "brightBlack": "#6B665D", "brightRed": "#C8321A", "brightGreen": "#3E6B3A", "brightYellow": "#8A6A1F", "brightBlue": "#2D4F7C", "brightMagenta": "#7A3B69", "brightCyan": "#2F6B6B", "brightWhite": "#141414" }

Env BASH_SILENCE_DEPRECATION_WARNING "1"

# A throwaway home, boxed home and file keystore: boxed never sees the real home folder or the system keychain.
Hide
Type 'export DEMO="$(mktemp -d /tmp/demo.XXXXXX)" && python3 scripts/demo/make_home.py "$DEMO/home" && mkdir "$DEMO/boxed"'
Enter
Type 'export PATH="${BOXED_DEMO_BIN:-$PWD/.venv/bin}:$PATH" HOME="$DEMO/home" BOXED_HOME="$DEMO/boxed" BOXED_KEYSTORE=insecure-file'
Enter
Type 'cd "$HOME/samples/app" && export PS1="$ " && unset PROMPT_COMMAND && clear'
Enter
Sleep 1s
Show

# 1. What the agents already saw.
Type "boxed audit"
Sleep 300ms
Enter
Sleep 7s

Hide
Type "clear"
Enter
Show

# 2. The report keeps counts and keyed hashes, never the values.
Type "boxed audit --html audit.html | tail -1"
Enter
Sleep 1500ms
Type "grep -cE 'AKIA|ghp_|sk-|xox' audit.html   # keys in the report"
Enter
Sleep 2500ms

Hide
Type "clear"
Enter
Show

# 3. Masking: markers go to the model, the values stay on this machine.
Type "cat .env"
Enter
Sleep 1500ms
Type "boxed mask .env"
Enter
Sleep 4500ms
