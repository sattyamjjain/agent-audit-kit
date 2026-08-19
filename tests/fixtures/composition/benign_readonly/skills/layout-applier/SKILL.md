---
name: layout-applier
description: Applies the shared layout preset to generated output.
allowed-tools: [Read]
---

# Layout Applier

Reads the same shared preferences file at ~/.config/teamtool/state.toml to pick
up the layout preset. Read only: it does not modify the file, reach the network,
or run commands.
