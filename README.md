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

You need Python 3.10 or newer and Git.

**macOS / Linux:**

```bash
git clone https://github.com/keeratrahman/cfgtool.git
cd cfgtool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/keeratrahman/cfgtool.git
cd cfgtool
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

- If `py` isn't found, use `python`. If neither works, install Python from [python.org](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"** during setup.
- If PowerShell says *running scripts is disabled on this system*, run this once and then activate again:
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- In Command Prompt (cmd) instead of PowerShell, activate with `.venv\Scripts\activate.bat`.

Activate the virtual environment again (the activate line above) each time you open a new terminal. On Windows, use `python` instead of `python3` in all the commands below.

## 2. Get an OpenRouter API key

<!-- TODO (Keerat): steps for creating an OpenRouter account and API key -->

### make an account on openrouter. Once you do that, it will prompt you with a key. Copy the key. You will need to put it in your .env file. If you forget to, just genereate a new key, set a limit on it if you want, no need to add in a credit card. I chose free models. 

&nbsp;

&nbsp;

&nbsp;

> **Use your own key.** Don't share keys. Free-model rate limits are per account, and a shared key means everyone runs out of quota together.

## 3. Put your key in `.env`

```bash
cp .env.example .env           # macOS / Linux / Windows PowerShell
copy .env.example .env         # Windows Command Prompt
```

Open `.env` in any text editor. Replace the placeholder with your key, and set `CFG_MODEL` to the number of the model **you** are testing (1, 2 or 3; see [Built-in models](#built-in-models-all-free-all-support-tool-calling)):

```
OPENROUTER_API_KEY=sk-or-v1-...
CFG_MODEL=2
```

After that, every run uses your model. The tool never switches to a different model on its own.

`.env` is gitignored, so your key stays on your machine. **Never commit it, and never paste it into chats or issues.** If a key leaks, delete it on OpenRouter and make a new one.

> **Windows / Notepad:** make sure the file is saved as `.env`, not `.env.txt`. In Notepad's *Save as* dialog, set "Save as type" to **All files**. To check, run `dir` (cmd) or `ls` (PowerShell) in the `cfgtool` folder and look for `.env` with no `.txt` at the end.

You can also set the key in your shell instead of using `.env`; a shell variable takes priority over `.env`. It only lasts until you close the terminal:

```
export OPENROUTER_API_KEY=sk-or-v1-...        # macOS / Linux
$env:OPENROUTER_API_KEY="sk-or-v1-..."        # Windows PowerShell
set OPENROUTER_API_KEY=sk-or-v1-...           # Windows Command Prompt
```

## 4. Run

```bash
# Ask your model (CFG_MODEL in .env) about a file
python cfg_agent.py sample.exe "What does the entry function do?"

# Use a different model for one run
python cfg_agent.py --model 3 sample.exe "Which arguments does 0x401020 take?"

# Ask all three models and compare the answers
python cfg_agent.py --compare sample.exe "Which instructions does 0x40100f depend on?"

# Analyze a short snippet of hex bytes instead of a file
python cfg_agent.py --hex "55 8b ec 8b 45 08 5d c3" "What does this function return?"

# Show the built-in models
python cfg_agent.py --list-models
```

Tool calls are printed to stderr as they happen. Add `-q` to hide them.

**If your model is busy or unavailable**, the tool retries a few times over about a minute, then tells you. Wait a few minutes and run the same command again.

**If the AI part isn't working at all** (no internet, key problems, daily limit reached), you can still analyze files without AI, using the plain CLI (see [Plain CLI](#plain-cli-no-llm) below). For example: `python cfg_cli.py sample.exe`

### If you see "stack warnings logged"

Sometimes the tool can't work out the stack layout of a function. When that happens, the run ends with:

```
[cfgtool] 2 stack warnings logged in cfgtool_warnings.log. Please send this file to Keerat.
```

**Please send `cfgtool_warnings.log` (in the `cfgtool` folder) to Keerat.** It contains only the date, the model, the sample's file name and SHA-256, and the function address. It never contains the sample itself. Once you've sent it you can delete it; a new one is created the next time a warning comes up. The answer from that run is still usable, but stack slot names (`stk_N`) in the affected functions may be off.

### Built-in models (all free, all support tool calling)

| # | Model |
|---|---|
| 1 | `nvidia/nemotron-3.5-super-vl:free` |
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
python cfg_cli.py app.exe --format json --sweep                   # include code not reached from the entry
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
| `no API key` | Create `.env` (step 3) in the `cfgtool` folder. On Windows, check it isn't saved as `.env.txt`. |
| `... is rate-limited right now` / `Your model ... didn't answer` | Normal for free models. Wait a few minutes and run the command again. If it keeps happening for hours, tell Keerat. |
| `hit its daily limit for free models` | Your OpenRouter account has used up today's free requests (each question uses several). It resets daily. Until then, use `cfg_cli.py` (no AI). |
| `can't reach OpenRouter` | Check your internet connection. Until then, use `cfg_cli.py` (no AI). |
| `Unexpected error ... Details saved to cfgtool_errors.log` | A bug in the tool. Send Keerat `cfgtool_errors.log` (in the `cfgtool` folder) and keep working with `cfg_cli.py` or another question. |
| `... timed out` | The free model is overloaded. Wait a few minutes and try again. |
| `Error code: 401` | Your key is wrong or was deleted. Check `.env`. |
| `Error code: 404` / `No endpoints found` / `not a valid model ID` | That free model was removed from OpenRouter. Tell Keerat so it can be replaced in the list. |
| `pip install` fails | Check `python3 --version` is 3.10 or newer, and that the virtual environment is active (step 1). Then run `pip install --upgrade pip` and try again. |
| `ERROR: ...` in the model's answer or tool output | The tool rejected the input. Common causes: a 64-bit file (not supported), a wrong path, or an address outside the file. The model usually retries on its own; if not, fix the file or address and ask again. |
| A Python traceback (many lines ending in `...Error: ...`) | A bug in the tool that slipped past the error handling. Send Keerat the **full** error text and the exact command you ran. |
| No error, but the answer looks wrong or incomplete | The free model may have misread the output, or the tool may not support that code yet (see Limitations). Try `--compare` or another model, and tell Keerat which sample and function it was. |

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
