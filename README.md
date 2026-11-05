# cfgtool

Builds **control-flow graphs** for 32-bit x86 code (raw bytes or 32-bit PE files). Each graph includes per-instruction **defs/uses (D/U)** and **data dependencies (DD)**. LLMs can use it as a tool: you ask a question about a binary, and the model calls the tool to look at the code.

There are three ways to use it:

| Script | What it does |
|---|---|
| `cfg_agent.py` | Ask a **free OpenRouter model** a question; the model uses the tool itself. *(Most people want this one.)* |
| `cfg_mcp_server.py` | The same tools as an MCP server, for Claude Code, Cursor and other MCP clients. |
| `cfg_cli.py` | Plain command line, no LLM. Outputs text, JSON or Graphviz DOT. |
| `cfg_check.py` | For the developer: scans samples and reports functions with stack warnings. |

---

## 1. Setup

You need Python 3.10 or newer.

```bash
git clone <repo-url>
cd cfgtool
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Get an OpenRouter API key

<!-- TODO (Keerat): steps for creating an OpenRouter account and API key -->

### make an account on openrouter. Once you do that, it will prompt you with a key. Copy the key. You will need to put it in your .env file. If you forget to, just genereate a new key, set a limit on it if you want, no need to add in a credit card. I chose free models. 

&nbsp;

&nbsp;

&nbsp;

> **Use your own key.** Don't share keys. Free-model rate limits are per account, and a shared key means everyone runs out of quota together.

## 3. Put your key in `.env`

```bash
cp .env.example .env
```

Open `.env` and replace the placeholder with your key:

```
OPENROUTER_API_KEY=sk-or-v1-...
```

`.env` is gitignored, so your key stays on your machine. **Never commit it, and never paste it into chats or issues.** If a key leaks, delete it on OpenRouter and make a new one.

(You can also `export OPENROUTER_API_KEY=...` in your shell instead; a shell variable takes priority over `.env`.)

## 4. Run

```bash
# Ask the default model about a file
python cfg_agent.py sample.exe "What does the entry function do?"

# Pick one of the three built-in models by number
python cfg_agent.py --model 2 sample.exe "Which arguments does 0x401020 take?"

# Ask all three models and compare the answers
python cfg_agent.py --compare sample.exe "Which instructions does 0x40100f depend on?"

# Analyze a short snippet of hex bytes instead of a file
python cfg_agent.py --hex "55 8b ec 8b 45 08 5d c3" "What does this function return?"

# Show the built-in models
python cfg_agent.py --list-models
```

Tool calls are printed to stderr as they happen. Add `-q` to hide them.

### If you see "stack warnings logged"

Sometimes the tool can't work out the stack layout of a function. When that happens, the run ends with:

```
[cfgtool] 2 stack warnings logged in cfgtool_warnings.log. Please send this file to Keerat.
```

**Please send `cfgtool_warnings.log` (in the `cfgtool` folder) to Keerat.** It contains only the date, the model, the sample's file name and SHA-256, and the function address. It never contains the sample itself. Once you've sent it you can delete it; a new one is created the next time a warning comes up. The answer from that run is still usable, but stack slot names (`stk_N`) in the affected functions may be off.

### Built-in models (all free, all support tool calling)

| # | Model |
|---|---|
| 1 (default) | `nvidia/nemotron-3.5-super-vl:free` |
| 2 | `cohere/north-mini-code:free` |
| 3 | `nvidia/nemotron-3.5-lightning:free` |

`--model` also accepts any other OpenRouter model ID. Free models are sometimes removed from OpenRouter; if one stops working, replace it in the `MODELS` list at the top of `cfg_agent.py`. When choosing a replacement on [openrouter.ai/models](https://openrouter.ai/models), filter by **Tools** support. `xingchen-agi/xing4.0-29b-a4b:free` also works, but it's slow.

---

## Other ways to run

### MCP server (Claude Code, Cursor, …)

```bash
claude mcp add cfg-builder -- python /full/path/to/cfgtool/cfg_mcp_server.py
```

The server offers the tools `list_functions`, `get_function` and `analyze_hex`. It doesn't need an OpenRouter key.

### Plain CLI (no LLM)

```bash
python cfg_cli.py sample.exe --format text
python cfg_cli.py sample.exe --format dot --mode cfg -o out.dot   # Lab 3 style
python cfg_cli.py sample.exe --format dot --mode ddg -o out.dot   # Lab 4 style
python cfg_cli.py --hex "55 8b ec 5d c3" --base 0x401000
```

Render a DOT file with: `dot -Tpng out.dot -o out.png`

---

## Reading the output

```
0x40100f  pop ebp     D: ebp, esp U: esp, stk_-4  DD: 0x401000, 0x40100a
```

- **D**: locations written. **U**: locations read.
- **DD**: addresses of the earlier instructions whose values this instruction reads. **START** means the value the location had on function entry.
- **stk_N**: stack slot at offset N from `esp` on function entry. `stk_4` is the first stack argument; negative offsets are locals and saved registers.
- **B0, B1, …**: basic blocks, each with its successor blocks.
- **`<kernel32!Sleep>`** after a call: the Windows API being called (resolved from the import table).
- **`note: assumed call at 0x… pops N bytes`**: the tool corrected its guess for a call so that the function's stack balances. This is informational.
- **`WARNING: stack …`**: the stack couldn't be balanced, so `stk_N` names after that point may be wrong.

## Troubleshooting

| Message | Fix |
|---|---|
| `no API key` | Create `.env` (step 3) in the `cfgtool` folder. |
| `... is rate-limited right now` | Normal for free models. Wait a minute, or use `--model` to pick another model. |
| `... timed out` | The free model is overloaded. Retry, or pick another model. |
| `Error code: 401` | Your key is wrong or was deleted. Check `.env`. |

## Limitations

- **32-bit x86 only.** 64-bit PEs are rejected.
- **Jump tables aren't followed** (`jmp [eax*4+...]`), so switch statements end in dead ends. Calls through registers or memory that aren't Windows imports (e.g. `call eax`, `call [ecx+8]`) show up as `indirect(...)`.
- Stack tracking doesn't handle stack alignment (`and esp, -16`) or `mov esp, ...`.
- How many stack arguments a call takes is worked out from `ret N` (for functions in the binary) or by counting pushes before the call (for Windows APIs and indirect calls). The guess is corrected automatically when the stack doesn't balance; otherwise a warning is shown.
- The free models sometimes misread correct tool output. Check important answers against the listing, or use `--compare`.

---

## For the developer: checking samples for warnings

`cfg_check.py` analyzes every function in a set of samples and reports which functions have stack warnings. It uses no LLM and no network, and it only reads the files; it never runs them.

```bash
python cfg_check.py samples/            # every PE under samples/ (recursive)
python cfg_check.py a.exe b.dll -v      # list each warning, with the sample's SHA-256
```

Lines in a partner's `cfgtool_warnings.log` are tab-separated: date, model, file name, SHA-256, function address, warning. Match the SHA-256 to your own copy of the sample and run `cfg_check.py` on it to reproduce.
