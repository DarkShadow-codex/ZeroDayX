#!/usr/bin/env python3
"""
ZeroDay Agent Interface
"""

import argparse
import asyncio
import contextlib
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from zeroday.config import codex, load_settings, persist_current
from zeroday.core.paths import run_dir_for
from zeroday.interface.cli_args import parse_arguments
from zeroday.interface.environment import (
    check_docker_installed,
    pull_docker_image,
    validate_environment,
)
from zeroday.interface.interactive import (
    InteractiveSetupUnavailableError,
    run_tui,
)
from zeroday.interface.scan_setup import (
    ModelConnectionError,
    preflight_model_connection,
    prepare_run,
    telemetry_start,
)
from zeroday.interface.update_check import (
    is_binary_install,
    notify_update,
    prompt_update_if_available,
    restart_after_update,
    start_background_check,
)
from zeroday.interface.utils import (
    build_final_stats_text,
)
from zeroday.llm.warmup import start_import_warmup, wait_for_import_warmup
from zeroday.telemetry import posthog, report_error, scarf, set_scan_phase
from zeroday.telemetry.logging import configure_dependency_logging


BEDROCK_MODEL_PREFIX = "bedrock/"
BEDROCK_MISSING_MODULE_ERROR = "No module named 'boto3'"
BEDROCK_EXTRA_HINT = (
    'Bedrock support is optional. Install it with: pipx install "zeroday-agent[bedrock]"'
)
VERTEX_MODEL_MARKER = "vertex"
VERTEX_MISSING_MODULE_ERROR = "No module named 'google"
VERTEX_EXTRA_HINT = (
    'Vertex AI support is optional. Install it with: pipx install "zeroday-agent[vertex]"'
)


import logging  # noqa: E402


logger = logging.getLogger(__name__)

_ROOT_SUBCOMMAND_HELP = """
Additional commands:
  zeroday cloud ...          Use the managed ZeroDay platform
  zeroday auth ...           Manage model-subscription sign-in
  zeroday view [RUN]         View a completed or running scan
  zeroday completions SHELL  Generate zsh, bash, or fish tab completion
"""


def _exception_messages(exc: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        messages.append(str(current))
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
    return tuple(messages)


def _provider_import_hint(exc: BaseException, model: str) -> str | None:
    """Return an install hint when *exc* is a missing provider dependency.

    Bedrock and Vertex AI ship as optional extras: Bedrock needs ``boto3`` and
    Vertex AI needs ``google-auth``. When either is absent, litellm may raise an
    ``ImportError``/``ModuleNotFoundError`` directly or wrap it in a connection
    error. Map the missing module back to the matching extra so the user knows
    what to install. Returns ``None`` for any unrelated error.
    """
    model_name = model.lower()
    messages = _exception_messages(exc)
    if any(
        BEDROCK_MISSING_MODULE_ERROR in message for message in messages
    ) and model_name.startswith(BEDROCK_MODEL_PREFIX):
        return BEDROCK_EXTRA_HINT
    if (
        any(VERTEX_MISSING_MODULE_ERROR in message for message in messages)
        and VERTEX_MODEL_MARKER in model_name
    ):
        return VERTEX_EXTRA_HINT
    return None


def _subscription_error_hint(exc: BaseException) -> str | None:
    """Return an actionable hint for a known ChatGPT-subscription error, or None."""
    if not codex.subscription_model(load_settings().llm.model):
        return None
    joined = " ".join(_exception_messages(exc)).lower()
    if "not supported when using codex with a chatgpt account" in joined:
        return (
            "This model isn't available on your ChatGPT subscription. "
            "Set ZERODAY_LLM to a model your plan includes (e.g. chatgpt/gpt-5.4)."
        )
    if (
        "error code: 401" in joined
        or "http 401" in joined
        or "unauthorized" in joined
        or "invalid_grant" in joined
    ):
        return (
            "Your ChatGPT sign-in has expired or was revoked. Sign in again:\n"
            "  zeroday auth login chatgpt"
        )
    return None


async def warm_up_llm(show_model_warning: bool = True) -> None:
    from agents.models.interface import ModelTracing

    from zeroday.config.models import (
        RECOMMENDED_MODEL_NAMES,
        configure_sdk_model_defaults,
        is_known_openai_bare_model,
        is_recommended_or_frontier_model,
    )
    from zeroday.core.inputs import make_model_settings

    console = Console()
    logger.info("Warming up LLM connection")

    raw_model = ""
    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm
        raw_model = (llm.model or "").strip()
        if (
            raw_model
            and "/" not in raw_model
            and not is_known_openai_bare_model(raw_model)
            and not llm.api_base
        ):
            warn_text = Text()
            warn_text.append("UNKNOWN MODEL NAME", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " is not a known OpenAI model. Bare names route to OpenAI by default.\n"
                "If you meant a non-OpenAI provider, use the '",
                style="white",
            )
            warn_text.append("<provider>/<model>", style="bold cyan")
            warn_text.append(
                "' form, e.g. 'anthropic/claude-opus-4-7', 'deepseek/deepseek-v4-pro'.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]ZERODAY",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )
            sys.exit(1)

        if show_model_warning and raw_model and not is_recommended_or_frontier_model(raw_model):
            warn_text = Text()
            warn_text.append("MODEL QUALITY WARNING", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " is not a recommended frontier model for ZeroDay.\n"
                "Security scans work best with:\n",
                style="white",
            )
            for recommended_model in RECOMMENDED_MODEL_NAMES:
                warn_text.append(f"• {recommended_model}\n", style="bold cyan")
            warn_text.append(
                "\nYou can continue, but weaker models may miss vulnerabilities "
                "or produce lower-quality findings.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]ZERODAY",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )

        await preflight_model_connection(raw_model, settings=settings)
        logger.info("LLM warm-up succeeded for model %s", (llm.model or "").strip())

        if settings.dedupe.model:
            from zeroday.report.dedupe import resolve_dedupe_model

            dedupe_model = settings.dedupe.model.strip()
            raw_model = dedupe_model
            deduper = resolve_dedupe_model(settings.dedupe, dedupe_model)
            # A dedicated dedupe model may route to another provider, which must
            # never receive the main endpoint's headers; it has its own
            # DEDUPE_LLM_EXTRA_HEADERS.
            deduper_settings = make_model_settings(
                None,
                model_name=dedupe_model,
                request_timeout=llm.timeout,
                prompt_cache=False,
                extra_headers=settings.dedupe.extra_headers,
                has_tools=False,
            )
            await asyncio.wait_for(
                deduper.get_response(
                    system_instructions="You are a helpful assistant.",
                    input="Reply with just 'OK'.",
                    model_settings=deduper_settings,
                    tools=[],
                    output_schema=None,
                    handoffs=[],
                    tracing=ModelTracing.DISABLED,
                    previous_response_id=None,
                    conversation_id=None,
                    prompt=None,
                ),
                timeout=llm.timeout,
            )
            logger.info("LLM warm-up succeeded for dedupe model %s", dedupe_model)

    except ModelConnectionError:
        logger.debug("Model route warm-up failed", exc_info=True)
        raise
    except Exception as exc:
        logger.debug("LLM warm-up failed", exc_info=True)
        raise ModelConnectionError(raw_model, exc) from exc


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    from zeroday.report.state import get_global_report_state

    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") == "completed"

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    view_text = Text()
    view_text.append("\n")
    view_text.append("View", style="dim")
    view_text.append("    ")
    view_text.append(f"zeroday view {args.run_name}", style="#22c55e")
    panel_parts.extend(["\n", view_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"zeroday --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]ZERODAY",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print(
        "[#60a5fa]zeroday.ai[/]  [dim]·[/]  "
        "[#60a5fa]docs.zeroday.ai[/]  [dim]·[/]  "
        "[#60a5fa]discord.gg/zeroday-ai[/]"
    )
    if not args.non_interactive:
        console.print(
            "[dim]Run a pentest in ZeroDay Cloud[/]  [#60a5fa]app.zeroday.ai[/]  [dim]·[/]  "
            "[dim]Enterprise[/]  [#60a5fa]zeroday.ai/demo[/]"
        )
    console.print()
    if not args.non_interactive:
        notify_update(console)


def _print_error_panel(title: str, message: str) -> None:
    console = Console()
    error_text = Text()
    error_text.append(title, style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(message, style="white")
    panel = Panel(
        error_text,
        title="[bold white]ZERODAY",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _print_model_connection_error(exc: BaseException, model_name: str) -> None:
    console = Console()
    error_text = Text()
    sub_hint = _subscription_error_hint(exc)
    if sub_hint is not None:
        border_style = "yellow"
        error_text.append("MODEL NOT AVAILABLE ON SUBSCRIPTION", style="bold yellow")
        error_text.append("\n\n", style="white")
        error_text.append(f"{sub_hint}\n", style="white")
        error_text.append(f"\nDetails: {exc}", style="dim white")
    else:
        border_style = "red"
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        hint = _provider_import_hint(exc, model_name)
        if hint is not None:
            error_text.append(f"\n{hint}\n", style="bold yellow")
        error_text.append(f"\nError: {exc}", style="dim white")

    panel = Panel(
        error_text,
        title="[bold white]ZERODAY",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _bootstrap_scan(args: argparse.Namespace) -> None:
    """Warm up the model and prepare the run for a non-interactive scan.

    Interactive launches skip this: the model preflight and run preparation
    happen inside the TUI so the interface paints immediately instead of
    waiting on a model round trip.
    """
    set_scan_phase("preflight")
    try:
        asyncio.run(warm_up_llm(show_model_warning=True))
    except ModelConnectionError as exc:
        report_error("model_connection_failed", exc)
        _print_model_connection_error(exc, exc.model_name)
        sys.exit(1)
    persist_current()
    try:
        prepare_run(args)
    except ValueError as e:
        report_error("scan_preparation_failed", e)
        _print_error_panel("SCAN PREPARATION FAILED", str(e))
        sys.exit(1)
    telemetry_start(args)


def main() -> None:
    with contextlib.suppress(ImportError):
        import dotenv

        dotenv.load_dotenv()

    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        try:
            parse_arguments()
        except SystemExit as exc:
            Console().print(_ROOT_SUBCOMMAND_HELP.strip(), markup=False)
            raise SystemExit(exc.code) from None

    # `zeroday view [<run>]` is a viewer-only subcommand, dispatched before the
    # scan argument parser (which requires a target) and before any scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "view":
        from zeroday.interface.viewer.cli import run_view

        run_view(sys.argv[2:])
        return

    # `zeroday auth …` manages model-subscription sign-in and exits; it needs no
    # target, Docker, or scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        from zeroday.interface.auth_cli import run_auth

        sys.exit(run_auth(sys.argv[2:]))

    # Generate native shell completion scripts before scan argument parsing.
    if len(sys.argv) > 1 and sys.argv[1] in ("completion", "completions"):
        from zeroday.interface.completions import run_completions

        sys.exit(run_completions(sys.argv[2:]))

    # `zeroday cloud …` drives the managed platform (app.zeroday.ai) and exits;
    # it needs no target, Docker, or scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "cloud":
        from zeroday.interface.cloud import run_cloud

        sys.exit(run_cloud(sys.argv[2:]))

    start_import_warmup()

    args = parse_arguments()

    start_background_check()
    if not args.non_interactive and prompt_update_if_available(Console()):
        if is_binary_install() and sys.platform != "win32":
            restart_after_update()
        sys.exit(0)

    check_docker_installed()
    pull_docker_image()
    validate_environment()

    # Everything below imports the scan engine; do not race the warm-up thread.
    wait_for_import_warmup()

    if args.non_interactive:
        _bootstrap_scan(args)

    from zeroday.report.state import get_global_report_state

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            from zeroday.interface.cli import run_cli

            asyncio.run(run_cli(args))
            # Headless runs have no user to quit: the agent either finished
            # (already beaconed as finished_by_tool) or stopped on its own.
            exit_reason = "agent_stopped"
        else:
            asyncio.run(run_tui(args))
    except InteractiveSetupUnavailableError as exc:
        exit_reason = "error"
        report_error("interactive_setup_unavailable", exc)
        _print_error_panel("INTERACTIVE SETUP UNAVAILABLE", str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as exc:
        exit_reason = "error"
        report_error("unhandled_exception", exc)
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            # Best-effort beacons on the way out. They reach the network, so a
            # second Ctrl-C lands here; abandon them rather than trading a clean
            # exit for a traceback.
            with contextlib.suppress(KeyboardInterrupt, Exception):
                posthog.end(report_state, exit_reason=exit_reason)
                scarf.end(report_state, exit_reason=exit_reason)

    if not args.run_name:
        # Setup mode where the user quit before starting a scan: nothing ran.
        notify_update(Console())
        return

    results_path = run_dir_for(args.run_name)

    display_completion_message(args, results_path)

    if args.non_interactive:
        report_state = get_global_report_state()
        if report_state and report_state.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
