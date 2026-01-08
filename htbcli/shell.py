import os
import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.pretty import pprint

from .storage import ChallengeStore, ensure_data_dir
from .config import load_config
from .ai import AIClient, AIConfig, Provider
from .parsers.nmap import parse_nmap
from .suggestions import next_steps_from_services, cheatsheets_for_services

console = Console()

WELCOME = """
[bold green]HTB Interactive Assistant[/bold green]
Type [bold]help[/bold] to see available commands. Type [bold]exit[/bold] to quit.
"""

HELP_TEXT = """
Commands:
  start <name> [type]        Start a new challenge (type: starting-point|machine)
  use <name>                 Switch to an existing challenge
  list                       List challenges
  show                       Show current challenge context
  status                     Show a concise status summary
  ask <question>             Ask AI any question in context of this challenge
  quiz <question>            Ask AI to answer a Starting Point quiz question
  note <text>                Add a note to this challenge
  load_nmap <path>           Load Nmap XML or gnmap and update services/context
  add_service <port>/<proto> <name>
                             Manually register a service (e.g., 445/tcp smb)
  set target <ip|host>       Set the current target (used in cheats/suggestions)
  add_cred <user> <pass> [service]
                             Save a credential for later use
  mark_tried <keyword>       Mark a technique/step as tried to avoid repeats
  suggest                    Suggest next steps based on known services/notes
  next                       Same as suggest but succinct
  cheats                     Show command templates for detected services
  help                       Show this help
  exit                       Exit the assistant
"""

class HTBShell:
    def __init__(self):
        ensure_data_dir()
        self.store = ChallengeStore()
        self.current: Optional[str] = None
        self.ai = self._init_ai()

    def _init_ai(self) -> AIClient:
        # Load project/user config
        cfg = load_config(Path.cwd())

        # Determine provider with precedence: env > config > default("auto")
        provider = os.environ.get("HTBCLI_PROVIDER") or str(cfg.get("provider", "auto"))
        provider = (provider or "auto").lower()

        # If config provides secrets and env is missing, set env for clients
        openai_cfg = cfg.get("openai", {}) if isinstance(cfg.get("openai"), dict) else {}
        if not os.environ.get("OPENAI_API_KEY") and openai_cfg.get("api_key"):
            os.environ["OPENAI_API_KEY"] = str(openai_cfg.get("api_key"))
        if not os.environ.get("HTBCLI_OPENAI_MODEL") and openai_cfg.get("model"):
            os.environ["HTBCLI_OPENAI_MODEL"] = str(openai_cfg.get("model"))

        ollama_cfg = cfg.get("ollama", {}) if isinstance(cfg.get("ollama"), dict) else {}
        if not os.environ.get("OLLAMA_BASE_URL") and ollama_cfg.get("base_url"):
            os.environ["OLLAMA_BASE_URL"] = str(ollama_cfg.get("base_url"))
        if not os.environ.get("HTBCLI_OLLAMA_MODEL") and ollama_cfg.get("model"):
            os.environ["HTBCLI_OLLAMA_MODEL"] = str(ollama_cfg.get("model"))

        # Choose provider
        if provider == "openai" or (provider == "auto" and os.environ.get("OPENAI_API_KEY")):
            config = AIConfig(provider=Provider.OPENAI, model=os.environ.get("HTBCLI_OPENAI_MODEL", "gpt-4o-mini"))
        elif provider == "ollama" or provider == "auto":
            # default to Ollama if openai key not present
            config = AIConfig(provider=Provider.OLLAMA, model=os.environ.get("HTBCLI_OLLAMA_MODEL", "llama3.1:8b"), base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"))
        else:
            config = AIConfig(provider=Provider.STUB)
        return AIClient(config)

    def run(self):
        console.print(Panel.fit(WELCOME, border_style="green"))
        self._maybe_warn_ethics()
        while True:
            try:
                prefix = f"[{self.current}]" if self.current else "[no-chal]"
                line = Prompt.ask(f"[bold cyan]{prefix}[/bold cyan] >")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[bold]Bye![/bold]")
                break
            if not line:
                continue
            self._dispatch(line.strip())

    def _maybe_warn_ethics(self):
        shown_flag = Path(self.store.data_dir, ".ethics_ack").exists()
        if not shown_flag:
            console.print(Panel("Use only on authorized HTB labs/targets. No auto-execution, suggestions only.", title="Ethics", border_style="yellow"))
            if Confirm.ask("Confirm you will only use this ethically and legally?", default=True):
                Path(self.store.data_dir, ".ethics_ack").write_text("ack")
            else:
                console.print("Exiting.")
                sys.exit(1)

    def _dispatch(self, line: str):
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit", ":q"):
            console.print("[bold]Bye![/bold]")
            raise SystemExit(0)
        elif cmd == "help":
            console.print(Panel.fit(HELP_TEXT, border_style="blue"))
        elif cmd == "start":
            self._cmd_start(args)
        elif cmd == "use":
            self._cmd_use(args)
        elif cmd == "list":
            self._cmd_list()
        elif cmd == "show":
            self._cmd_show()
        elif cmd == "status":
            self._cmd_status()
        elif cmd == "note":
            self._cmd_note(args)
        elif cmd == "ask":
            self._cmd_ask(args, mode="general")
        elif cmd == "quiz":
            self._cmd_ask(args, mode="quiz")
        elif cmd == "load_nmap":
            self._cmd_load_nmap(args)
        elif cmd == "add_service":
            self._cmd_add_service(args)
        elif cmd == "set":
            self._cmd_set(args)
        elif cmd == "add_cred":
            self._cmd_add_cred(args)
        elif cmd == "mark_tried":
            self._cmd_mark_tried(args)
        elif cmd == "suggest":
            self._cmd_suggest(verbose=True)
        elif cmd == "next":
            self._cmd_suggest(verbose=False)
        elif cmd == "cheats":
            self._cmd_cheats()
        else:
            console.print(f"Unknown command: {cmd}. Type 'help'.")

    def _require_current(self) -> Dict[str, Any]:
        if not self.current:
            console.print("[red]No challenge active. Use 'start <name>' or 'use <name>'.[/red]")
            raise RuntimeError("no current challenge")
        return self.store.load(self.current)

    def _cmd_start(self, args: List[str]):
        if not args:
            console.print("Usage: start <name> [type]")
            return
        name = args[0]
        ctype = args[1] if len(args) > 1 else "machine"
        if self.store.exists(name):
            console.print(f"[yellow]Challenge '{name}' already exists. Switching to it.[/yellow]")
        else:
            self.store.create(name, {"type": ctype, "notes": [], "services": [], "artifacts": {}, "history": []})
            console.print(f"[green]Created challenge '{name}' ({ctype}).[/green]")
        self.current = name

    def _cmd_use(self, args: List[str]):
        if not args:
            console.print("Usage: use <name>")
            return
        name = args[0]
        if not self.store.exists(name):
            console.print(f"[red]Challenge '{name}' not found.[/red]")
            return
        self.current = name
        console.print(f"[green]Switched to '{name}'.[/green]")

    def _cmd_list(self):
        rows = self.store.list()
        table = Table(title="Challenges")
        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Updated")
        for r in rows:
            table.add_row(r["name"], r.get("type", ""), r.get("updated", ""))
        console.print(table)

    def _cmd_show(self):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        console.print(Panel.fit(json.dumps(ctx, indent=2), title=f"{self.current}", border_style="cyan"))

    def _cmd_note(self, args: List[str]):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if not args:
            console.print("Usage: note <text>")
            return
        text = " ".join(args)
        ctx.setdefault("notes", []).append(text)
        self.store.save(self.current, ctx)
        console.print("[green]Note added.[/green]")

    def _cmd_ask(self, args: List[str], mode: str):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if not args:
            console.print(f"Usage: {mode} <question>")
            return
        question = " ".join(args)
        system = self._build_system_prompt(ctx, mode)
        answer = self.ai.ask(system=system, question=question)
        console.print(Panel.fit(answer, title="AI", border_style="magenta"))
        ctx.setdefault("history", []).append({"mode": mode, "q": question, "a": answer})
        self.store.save(self.current, ctx)

    def _build_system_prompt(self, ctx: Dict[str, Any], mode: str) -> str:
        base = (
            "You are an ethical HTB assistant. Only provide legal guidance for authorized labs. "
            "You must respond with concrete, copy-pasteable commands, short explanations, and risk notes. "
            "Never claim to have run commands."
        )
        if mode == "quiz":
            base += " Focus on Hack The Box Starting Point quiz answers. Be concise and cite the relevant service/step."
        srv = ctx.get("services", [])
        notes = ctx.get("notes", [])
        tried = ctx.get("tried", [])
        creds = ctx.get("creds", [])
        target = ctx.get("target")
        base += f"\nTarget: {json.dumps(target)}\nKnown services: {json.dumps(srv)}\nCreds: {json.dumps(creds)}\nNotes: {json.dumps(notes)}\nTried (avoid repeating): {json.dumps(tried)}\nGoal: Obtain user.txt/root.txt flags with minimal repetition."
        return base

    def _cmd_load_nmap(self, args: List[str]):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if not args:
            console.print("Usage: load_nmap <path-to-xml-or-gnmap>")
            return
        path = Path(args[0]).expanduser()
        if not path.exists():
            console.print(f"[red]File not found: {path}[/red]")
            return
        try:
            services = parse_nmap(path)
        except Exception as e:
            console.print(f"[red]Failed to parse: {e}[/red]")
            return
        # merge services by (port/proto)
        merged = {f"{s['port']}/{s['proto']}": s for s in ctx.get("services", [])}
        for s in services:
            merged[f"{s['port']}/{s['proto']}"] = s
        ctx["services"] = list(merged.values())
        ctx.setdefault("artifacts", {})["nmap"] = str(path)
        self.store.save(self.current, ctx)
        console.print(f"[green]Loaded {len(services)} services from Nmap.[/green]\nKnown services updated. Run 'suggest' or 'cheats'.")

    def _cmd_suggest(self, verbose: bool = True):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        steps = next_steps_from_services(ctx.get("services", []), verbose=verbose)
        # Filter out steps marked as tried
        tried = set(map(str.lower, ctx.get("tried", [])))
        if not steps:
            console.print("[yellow]No suggestions yet. Add notes or load Nmap first.[/yellow]")
            return
        shown = 0
        for title, content in steps:
            blob = f"{title}\n{content}".lower()
            if any(t in blob for t in tried):
                continue
            console.print(Panel(content, title=title, border_style="green"))
            shown += 1
        if shown == 0:
            console.print("[yellow]All known suggestions were marked as tried. Add new intel or load Nmap for more paths.[/yellow]")

    def _cmd_cheats(self):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        cheats = cheatsheets_for_services(ctx.get("services", []))
        if not cheats:
            console.print("[yellow]No cheats available yet. Load services first.[/yellow]")
            return
        for title, content in cheats:
            console.print(Panel(content, title=title, border_style="blue"))

    def _cmd_add_service(self, args: List[str]):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if len(args) < 2:
            console.print("Usage: add_service <port>/<proto> <name>")
            return
        pp = args[0]
        name = " ".join(args[1:])
        if "/" not in pp:
            console.print("Format must be <port>/<proto>, e.g., 445/tcp")
            return
        port_str, proto = pp.split("/", 1)
        try:
            port = int(port_str)
        except ValueError:
            console.print("Port must be an integer")
            return
        # merge into services by key
        key = f"{port}/{proto}"
        merged = {f"{s['port']}/{s['proto']}": s for s in ctx.get("services", [])}
        merged[key] = {"port": port, "proto": proto, "state": "open", "service": name, "product": "", "version": ""}
        ctx["services"] = list(merged.values())
        self.store.save(self.current, ctx)
        console.print(f"[green]Service added:[/green] {key} {name}")

    def _cmd_set(self, args: List[str]):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if len(args) < 2 or args[0] != "target":
            console.print("Usage: set target <ip|host>")
            return
        ctx["target"] = args[1]
        self.store.save(self.current, ctx)
        console.print(f"[green]Target set:[/green] {ctx['target']}")

    def _cmd_add_cred(self, args: List[str]):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if len(args) < 2:
            console.print("Usage: add_cred <user> <pass> [service]")
            return
        user = args[0]
        pwd = args[1]
        svc = args[2] if len(args) > 2 else ""
        ctx.setdefault("creds", []).append({"user": user, "pass": pwd, "service": svc})
        self.store.save(self.current, ctx)
        console.print(f"[green]Credential saved for[/green] {user} ({svc or 'generic'})")

    def _cmd_mark_tried(self, args: List[str]):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        if not args:
            console.print("Usage: mark_tried <keyword>")
            return
        kw = " ".join(args).strip()
        if not kw:
            console.print("Provide a non-empty keyword")
            return
        tried = ctx.setdefault("tried", [])
        if kw not in tried:
            tried.append(kw)
            self.store.save(self.current, ctx)
        console.print(f"[green]Marked as tried:[/green] {kw}")

    def _cmd_status(self):
        try:
            ctx = self._require_current()
        except RuntimeError:
            return
        summary = {
            "target": ctx.get("target"),
            "services": [f"{s.get('port')}/{s.get('proto')} {s.get('service')}" for s in ctx.get("services", [])],
            "creds": ctx.get("creds", []),
            "notes_count": len(ctx.get("notes", [])),
            "tried": ctx.get("tried", []),
        }
        console.print(Panel.fit(json.dumps(summary, indent=2), title=f"status: {self.current}", border_style="cyan"))
