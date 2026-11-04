# A workspace in your terminal

Start with `./bypass`, or reopen a connected application with `./bypass --project /path/to/app`. The terminal keeps four things visible: the selected repository/app/model, the activity timeline, the current and next actions, and the command bar.

The current workspace is centered on the connected application. `/review` runs the selected code, app, or combined audit; `/blackbox` explicitly runs the authorized app audit. Legacy fixture walkthroughs are not presented in the customer menu or suggested actions.

| What you want | Interaction |
| --- | --- |
| Discover available actions | Type `/`, filter by name, then arrows + Enter |
| Take the suggested next step | Press Enter at the command bar |
| Understand what just ran | Read the operation row and elapsed time; Ctrl+O expands details |
| Follow setup or an audit | Read the checklist, completion percentage, active work and saved evidence |
| Return to DNS setup | `/app` shows the existing app and its ownership challenge |
| See previous work | PgUp/PgDn for this session; `/history` for saved project events |
| Stop a waiting operation | Esc; Enter also skips a model connection check |
| Exit | `/quit` or Ctrl+C; project state and a session transcript are retained |

Menus accept arrow keys or numbers. The input supports editing, long pasted paths, bracketed multiline paste, and session command history. The layout adapts to narrower windows; the task list becomes compact while the command bar remains visible. Use a terminal at least 40 columns by 15 rows for the full-screen workspace.

`BYPASS_PLAIN=1 ./bypass` preserves a plain scrolling interface, including for screen readers. `TERM=dumb` also uses plain mode. `NO_COLOR=1` removes color. Scripted commands and `--json` keep their original output and exit codes.

The workspace offers defined commands and guided actions. Free-form model conversation remains in Muse. Use `/engine` to inspect the isolated source-review runtime and `/review` to run the selected source, live, or combined audit. The header identifies the Muse-focused product and the sidebar identifies the selected model and local evidence location.

## Interaction references

The command palette follows the discoverable slash-command pattern documented by [OpenCode's TUI](https://opencode.ai/docs/tui/). Transcript expansion, command history, task visibility and interrupt controls draw on [Claude Code's interactive mode](https://code.claude.com/docs/en/interactive-mode). [Strix](https://github.com/usestrix/strix) is a reference for an integrated security-testing CLI, not a claim of engine parity.

Bypass reports actual operation timing and completed stages. It does not invent completion percentages or display a fabricated model thought process.
