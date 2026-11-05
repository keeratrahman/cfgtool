# cfgtool

cfgtool lets an AI model answer questions about 32-bit Windows programs. You ask a question about a file, and the model uses this tool to read the program's code: its functions, control flow, and which instructions depend on which.

Each of us tests **one** AI model. Follow the steps below once, then go to [Asking questions](#asking-questions).

---

## Setup (one time)

### Step 1: Install

You need **Python 3.10 or newer** and **Git**.

**Mac / Linux:**

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

Windows problems?
- `py` not found → use `python` instead. If that doesn't work either, install Python from [python.org](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"**.
- *"running scripts is disabled on this system"* → run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then run the activate line again.
- Using Command Prompt instead of PowerShell → activate with `.venv\Scripts\activate.bat`.

### Step 2: Get an OpenRouter key

Make an account on [OpenRouter](https://openrouter.ai). Once you do that, it will prompt you with a key. Copy the key; you will put it in your `.env` file in step 3. If you lose it, just generate a new key. You can set a spending limit on it if you want. No credit card is needed, because we use free models.

**Use your own key, not someone else's.** Each account has its own daily limit (see below).

### The daily limit

- A free OpenRouter account gets **50 AI requests per day**.
- One verdict run uses about **5–10 requests**, so you get roughly **5–10 runs per day**. A verdict on each of your 3 file versions fits, with some room to spare.
- The limit **resets at midnight UTC** (7 PM US Eastern time in winter, 8 PM in summer).
- When you run out, the tool says `hit its daily limit for free models`. Wait for the reset, or use `cfg_cli.py` (no AI) in the meantime.
- Optional: an account that has bought at least 10 credits gets 1,000 free-model requests per day. This costs money and isn't needed for our testing.

### Step 3: Create your `.env` file

In the `cfgtool` folder, copy the example file:

```bash
cp .env.example .env        # Mac / Linux / Windows PowerShell
copy .env.example .env      # Windows Command Prompt
```

Open `.env` in a text editor and fill in **your key** and **your model number**:

```
OPENROUTER_API_KEY=sk-or-v1-paste-your-key-here
CFG_MODEL=2
```

Model numbers:

| `CFG_MODEL` | Model |
|---|---|
| 1 | `nvidia/nemotron-3.5-super-vl:free` |
| 2 | `cohere/north-mini-code:free` |
| 3 | `nvidia/nemotron-3.5-lightning:free` |

That's it. Every question you ask now goes to your model, and the tool never switches to a different one.

> **Windows / Notepad:** save the file as `.env`, **not** `.env.txt`. In Notepad's *Save as* window, set "Save as type" to **All files**.

> **Keep your key private.** `.env` is never uploaded to GitHub. Don't paste your key into chats. If it leaks, delete it on OpenRouter and make a new one.

---

## Asking questions

Every time you open a new terminal, first go to the `cfgtool` folder and activate the environment:

```bash
cd cfgtool
source .venv/bin/activate      # Mac / Linux
.venv\Scripts\Activate.ps1     # Windows PowerShell
```

### Get a verdict: has malicious code been put in?

Give just the file name:

```bash
python cfg_agent.py sample.exe
```

(On Mac/Linux, use `python3` if `python` isn't found.)

The model explores the program with the tool, explains what it found, and ends with a verdict block like this:

```
VERDICT: SUSPICIOUS
CONFIDENCE: MEDIUM
EVIDENCE:
- 0x401a20: allocates executable memory and copies bytes into it
- 0x401b00: calls CreateRemoteThread
OBFUSCATION: many indirect calls; possibly packed
```

| Line | Meaning |
|---|---|
| `VERDICT` | `MALICIOUS`, `SUSPICIOUS`, `CLEAN`, or `UNSURE` (couldn't see enough of the code to decide). |
| `CONFIDENCE` | How sure the model is: `LOW`, `MEDIUM`, or `HIGH`. |
| `EVIDENCE` | Addresses and what the model found there. |
| `OBFUSCATION` | Whether the model thinks the code is hidden or obfuscated. |

**When testing your 3 versions of the file**, run this same command on each version and record the `VERDICT`, `CONFIDENCE` and `OBFUSCATION` lines. Don't expect correct verdicts on the obfuscated versions yet; what matters is recording what the model says. Worse answers on obfuscated files are expected. Crashes and error logs are not; send those to Keerat.

### Ask your own question

```bash
python cfg_agent.py sample.exe "Which Windows APIs does the function at 0x401000 call?"

# Your own question, plus a verdict block at the end
python cfg_agent.py --verdict sample.exe "Look closely at the function at 0x401000"

# A few hex bytes instead of a file
python cfg_agent.py --hex "55 8b ec 8b 45 08 5d c3" "What does this function return?"

# Hide the tool-call messages and show only the answer
python cfg_agent.py -q sample.exe
```

While it works, you'll see lines like `[tool] list_functions(...)`. That's the model using the tool. The answer is printed at the end.

**Remember the daily limit:** 50 requests per day, and a verdict run uses about 5–10 of them (see [The daily limit](#the-daily-limit)). Plan your testing so you don't run out halfway through.

**Can't use the AI right now?** (no internet, key problem, daily limit) You can still look at a file's code without AI:

```bash
python cfg_cli.py sample.exe
```

---

## When something goes wrong

| You see | What to do |
|---|---|
| `no API key` | Your `.env` file is missing or misnamed (step 3). On Windows, check it isn't called `.env.txt`. |
| `rate-limited`, `timed out`, or `Your model ... didn't answer` | Free models are often busy. Wait a few minutes and run the same command again. If it keeps happening for hours, tell Keerat. |
| `daily limit for free models` | You've used today's 50 free requests. The limit resets at midnight UTC (7 PM US Eastern in winter). Until then, use `python cfg_cli.py sample.exe`. |
| `can't reach OpenRouter` | Check your internet connection. |
| `rejected your API key` / `Error code: 401` | Your key is wrong or was deleted. Check `.env`, or make a new key. |
| `Error code: 404` / `No endpoints found` | Your model was removed from OpenRouter. Tell Keerat. |
| `ERROR: ...` about the file or an address | The file isn't supported (e.g. a 64-bit program) or the address is wrong. The model usually corrects itself; if not, check the file or address. |
| `pip install` fails | Check that `python --version` shows 3.10 or newer and that the environment is active (step 1), then run `pip install --upgrade pip` and try again. |

### What to send Keerat

| If… | Send |
|---|---|
| The run ends with `stack warnings logged in cfgtool_warnings.log` | The file `cfgtool_warnings.log` from the `cfgtool` folder. (It doesn't contain the sample itself.) |
| You see `Details saved to cfgtool_errors.log` | The file `cfgtool_errors.log` from the `cfgtool` folder. |
| You see a long Python error (a "traceback") | The full error text and the command you ran. |
| The answer looks wrong or incomplete | The sample name, your question, and which function it was about. |

You can delete the log files after sending them.

---

## Reading the tool's output

You'll see this in the `[tool]` output, or when you run `cfg_cli.py`:

```
0x40100f  pop ebp     D: ebp, esp U: esp, stk_-4  DD: 0x401000, 0x40100a
```

- **D**: what the instruction writes. **U**: what it reads.
- **DD**: the earlier instructions whose values it reads. **START** means "the value at the start of the function".
- **stk_N**: a stack slot. `stk_4` is the first argument; negative numbers are local variables and saved registers.
- **B0, B1, …**: basic blocks (straight-line chunks of code) and where each one jumps to.
- **`<kernel32!Sleep>`**: the Windows API being called.
- **`note: ...`**: the tool fixed one of its own guesses. Nothing to worry about.
- **`WARNING: stack ...`**: stack slot names after this point may be wrong.

## Limitations

- Only **32-bit** programs. 64-bit programs are rejected.
- Switch statements (jump tables) aren't followed, so parts of some functions may be missing.
- Calls through registers that aren't Windows APIs show up as `indirect(...)`.
- Free models sometimes misread the tool's output. Double-check important answers.

---

## Other ways to run

### Plain CLI (no AI, no key needed)

```bash
python cfg_cli.py sample.exe                                      # readable listing
python cfg_cli.py sample.exe --format dot --mode cfg -o out.dot   # Lab 3 style graph
python cfg_cli.py sample.exe --format dot --mode ddg -o out.dot   # Lab 4 style graph
python cfg_cli.py sample.exe --format json --sweep                # JSON, including unreachable code
python cfg_cli.py --hex "55 8b ec 5d c3" --base 0x401000
```

Turn a `.dot` file into a picture with Graphviz: `dot -Tpng out.dot -o out.png`

### MCP server (Claude Code, Cursor, …)

```bash
claude mcp add cfg-builder -- python /full/path/to/cfgtool/cfg_mcp_server.py
```

Provides the tools `list_functions`, `get_function` and `analyze_hex`. It doesn't need an OpenRouter key.

---

## For Keerat (developer notes)

**Check samples for stack warnings** (no AI, no network; it only reads the files and never runs them):

```bash
python cfg_check.py samples/        # every PE file in the folder
python cfg_check.py a.exe -v        # list each warning with the sample's SHA-256
```

Each line in a `cfgtool_warnings.log` is tab-separated: date, model, file name, SHA-256, function address, warning. Match the SHA-256 to your copy of the sample and run `cfg_check.py` on it to reproduce.

**Replacing a removed model:** edit the `MODELS` list at the top of `cfg_agent.py`. Pick a free model on [openrouter.ai/models](https://openrouter.ai/models) with **Tools** support. `xingchen-agi/xing4.0-29b-a4b:free` works but is slow.

**Other options:** `--model N` (use a different model for one run), `--compare` (ask all three models), `--list-models`.
