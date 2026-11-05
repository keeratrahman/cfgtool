#!/usr/bin/env python3
"""Ask a free OpenRouter model a question about a binary; the model calls the CFG tools itself.

Setup:
  pip install -r requirements.txt
  cp .env.example .env        # then put YOUR OpenRouter key in .env

Examples:
  python cfg_agent.py sample.exe "What does the entry function do?"        # default model
  python cfg_agent.py --model 2 sample.exe "..."                           # model #2 from MODELS
  python cfg_agent.py --compare sample.exe "..."                           # ask all 3 models
  python cfg_agent.py --hex "55 8b ec 8b 45 08 5d c3" "What does this return?"
  python cfg_agent.py --list-models

--model also accepts any OpenRouter model ID (https://openrouter.ai/models, filter by "Tools").
"""
import argparse
import os
import sys
import time

from openai import (APIConnectionError, APIError, APITimeoutError, InternalServerError, OpenAI,
                    RateLimitError)

from cfg_tools import TOOL_SCHEMAS, dispatch

TRANSIENT = (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError)

# Free models with tool-calling support, tested against this tool (Nov 2026).
# Free models come and go on OpenRouter; edit this list if one disappears.
MODELS = [
    "nvidia/nemotron-3.5-super-vl:free",
    "cohere/north-mini-code:free",
    "nvidia/nemotron-3.5-lightning:free",
]


def load_dotenv(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    """Minimal .env reader (KEY=value lines). Real environment variables win."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


def resolve_model(m):
    """'1'..'3' pick from MODELS; anything else is used as an OpenRouter model ID."""
    if m and m.isdigit() and 1 <= int(m) <= len(MODELS):
        return MODELS[int(m) - 1]
    return m or MODELS[0]

SYSTEM = """You are a reverse-engineering assistant for 32-bit x86 code.
You have tools that build control-flow graphs with def/use and data-dependency info.
Rules:
- For a file: call list_functions first, then get_function on the functions you need.
- Addresses are hex strings like "0x401000".
- If a tool returns "ERROR: ...", read it, fix the arguments and try again.
- Base your answer only on tool output. Cite instruction addresses."""


def _complete(client, model, messages, verbose, waits=(5, 15, 30)):
    """Chat completion with backoff: free models are often rate-limited (429) or slow."""
    for attempt in range(len(waits) + 1):
        try:
            resp = client.chat.completions.create(model=model, messages=messages,
                                                  tools=TOOL_SCHEMAS, tool_choice="auto")
            if resp.choices:
                return resp
            e = RuntimeError("empty response from provider")
        except TRANSIENT as err:
            e = err
        if attempt == len(waits):
            raise e
        if verbose:
            print("[retry] %s: %s; waiting %ds" % (type(e).__name__, str(e)[:80], waits[attempt]),
                  file=sys.stderr)
        time.sleep(waits[attempt])


def run(model, question, max_steps=12, verbose=True):
    client = OpenAI(base_url="https://openrouter.ai/api/v1",
                    api_key=os.environ["OPENROUTER_API_KEY"], timeout=120, max_retries=2)
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": question}]
    for _ in range(max_steps):
        resp = _complete(client, model, messages, verbose)
        msg = resp.choices[0].message
        if not msg.tool_calls:
            return msg.content or ""
        messages.append({"role": "assistant", "content": msg.content or "",
                         "tool_calls": [{"id": tc.id, "type": "function",
                                         "function": {"name": tc.function.name,
                                                      "arguments": tc.function.arguments or "{}"}}
                                        for tc in msg.tool_calls]})
        for tc in msg.tool_calls:
            if verbose:
                print("[tool] %s(%s)" % (tc.function.name, tc.function.arguments), file=sys.stderr)
            result = dispatch(tc.function.name, tc.function.arguments)
            if verbose:
                print("       -> %d chars%s" % (len(result), ", ERROR" if result.startswith("ERROR") else ""),
                      file=sys.stderr)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
    return "(stopped after %d tool rounds without a final answer)" % max_steps


def ask(model, q, max_steps, verbose):
    """Run one model; return its answer or a one-line error (never raises API errors)."""
    try:
        return run(model, q, max_steps, verbose)
    except RateLimitError:
        return ("ERROR: %s is rate-limited right now (common for :free models). "
                "Try again in a minute or use another model." % model)
    except APITimeoutError:
        return "ERROR: %s timed out. Try again or use another model." % model
    except (APIError, RuntimeError) as e:
        return "ERROR from OpenRouter (%s): %s" % (model, e)


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description="Ask free OpenRouter models about x86-32 code using the CFG tools.")
    p.add_argument("args", nargs="*", metavar="[FILE] QUESTION",
                   help="binary file and question (just the question when using --hex)")
    p.add_argument("--hex", help="analyze these hex bytes instead of a file")
    p.add_argument("--model", default=os.environ.get("CFG_MODEL"),
                   help="1-%d (from MODELS) or an OpenRouter model ID; default: model 1" % len(MODELS))
    p.add_argument("--compare", action="store_true", help="ask every model in MODELS and print all answers")
    p.add_argument("--list-models", action="store_true", help="show the built-in models and exit")
    p.add_argument("--max-steps", type=int, default=12)
    p.add_argument("-q", "--quiet", action="store_true", help="don't print tool calls")
    a = p.parse_args()

    if a.list_models:
        for k, m in enumerate(MODELS, 1):
            print("%d  %s" % (k, m))
        return
    if not os.environ.get("OPENROUTER_API_KEY"):
        p.error("no API key: put OPENROUTER_API_KEY=sk-or-... in .env (see .env.example) or export it")
    if a.hex:
        if not a.args:
            p.error("give a question")
        q = "Machine code (hex, load address 0x401000): %s\n\n%s" % (a.hex, " ".join(a.args))
    else:
        if len(a.args) < 2:
            p.error("give a file and a question (or use --hex)")
        if not os.path.isfile(a.args[0]):
            p.error("file not found: %s" % a.args[0])
        q = "Binary file path: %s\n\n%s" % (os.path.abspath(a.args[0]), " ".join(a.args[1:]))

    if a.compare:
        failed = 0
        for k, m in enumerate(MODELS, 1):
            print("\n===== [%d] %s" % (k, m), flush=True)
            answer = ask(m, q, a.max_steps, not a.quiet)
            failed += answer.startswith("ERROR")
            print(answer, flush=True)
        sys.exit(1 if failed == len(MODELS) else 0)
    answer = ask(resolve_model(a.model), q, a.max_steps, not a.quiet)
    print(answer)
    sys.exit(1 if answer.startswith("ERROR") else 0)


if __name__ == "__main__":
    main()
