# HTB Interactive Assistant (Single CLI)

One interactive terminal tool to manage Hack The Box challenges: start/use challenges, keep per-challenge context, ask AI questions, answer Starting Point quiz questions, load Nmap output, and get next steps and cheatsheets.

Use ethically and only against authorized HTB targets.

## Features
- Single interactive CLI (REPL). Start once, do everything inside it.
- Challenge context stored locally per challenge in `~/.htbcli/challenges/<name>.json`.
- AI provider pluggable: OpenAI or local Ollama.
- Nmap XML/gnmap parsing to detect services and suggest next steps.
- Built-in suggestions and cheatsheets for common services.

## Requirements
- Python 3.9+
- pip
- Optional for AI:
  - OpenAI: environment variable `OPENAI_API_KEY`
  - Ollama: running locally with models (e.g. `llama3.1:8b`), set `OLLAMA_BASE_URL` if non-default

## Install
```
pip install -r requirements.txt
```

## Run
```
python -m htbcli
```

On first run you must confirm the ethics notice.

## Environment variables (optional)
- `HTBCLI_PROVIDER` = `openai` | `ollama` | `auto` (default: `auto`)
- `HTBCLI_OPENAI_MODEL` (default: `gpt-4o-mini`)
- `HTBCLI_OLLAMA_MODEL` (default: `llama3.1:8b`)
- `OPENAI_API_KEY` (when using OpenAI)
- `OLLAMA_BASE_URL` (when using Ollama; default `http://localhost:11434`)

## Project/User config.yaml (alternative to env vars)
You can configure the CLI using YAML files without setting env vars.

- Precedence (highest to lowest):
  - Environment variables
  - Project config: `./.htbcli/config.yaml`
  - User config: `~/.htbcli/config.yaml`
  - Built-in defaults

Example file is provided at `examples/config.example.yaml`.

Project-local setup (Linux/macOS):
```
mkdir -p .htbcli
cp examples/config.example.yaml .htbcli/config.yaml
$EDITOR .htbcli/config.yaml
```

Example contents:
```yaml
provider: openai    # or: ollama or auto
openai:
  api_key: "sk-..."
  model: "gpt-4o-mini"
ollama:
  base_url: "http://localhost:11434"
  model: "llama3.1:8b"
```

Note: `.htbcli/` is gitignored in this repo to avoid committing secrets.

## Commands inside the REPL
- `start <name> [type]`  Start a new challenge, e.g. `start lame machine`
- `use <name>`           Switch to an existing challenge
- `list`                 List challenges
- `show`                 Show current challenge JSON context
- `ask <question>`       Ask AI in the context of the current challenge
- `quiz <question>`      Ask AI to answer HTB Starting Point quiz questions
- `note <text>`          Add a note
- `load_nmap <path>`     Load Nmap XML or gnmap output
- `suggest`              Verbose next steps based on detected services
- `next`                 Concise next steps
- `cheats`               Command templates for detected services
- `help`                 Show help
- `exit`                 Quit

## Typical workflow
1. Start the CLI: `python -m htbcli`
2. `start <challenge-name> [starting-point|machine]`
3. Run your scans externally (e.g., `nmap -p- -sC -sV -oA scan <target>`) and then `load_nmap scan.xml`
4. `suggest` or `cheats` for next moves
5. Use `ask "How to enumerate SMB anon?"` for tailored guidance
6. Add `note` as you find creds/paths. Use `quiz` for Starting Point Q&A.

## Notes
- The tool does not execute commands; it only suggests. You run commands in your own terminal.
- Data is stored locally under your user profile (`~/.htbcli/challenges`).
- If neither OpenAI nor Ollama are configured, the AI replies will explain how to configure a provider.

## Roadmap (optional)
- Upload and parse tool outputs beyond Nmap
- Auto-summarize notes/history
- Per-challenge attachments and tagging
