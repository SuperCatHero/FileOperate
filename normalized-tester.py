# %%
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.text import Text


# -----------------------------
# Configuration
# -----------------------------

@dataclass(frozen=True)
class Theme:
    user_title: str = "User"
    user_style: str = "bold blue"

    assistant_title: str = "Assistant"
    assistant_style: str = "bold green"

    tool_call_title: str = "Tool Call"
    tool_call_style: str = "bold magenta"

    tool_output_title: str = "Tool Output"
    tool_output_style: str = "bold yellow"

    file_title: str = "File Artifact"
    file_style: str = "bold cyan"

    system_title: str = "System"
    system_style: str = "dim"

    divider_style: str = "dim white"


# -----------------------------
# Renderer
# -----------------------------

class RichAgentRenderer:
    """
    Render streamed events and final outputs from LangChain/LangGraph-style agents
    using Rich panels.

    Design goals:
    - Minimal dependencies on LangGraph internals (e.g., Overwrite wrapper)
    - Robust to multiple message/content formats
    - Deterministic, readable output with safe truncation
    """

    def __init__(
        self,
        console: Optional[Console] = None,
        theme: Theme = Theme(),
        markdown_lexer: str = "markdown",
        syntax_theme: str = "monokai",
        file_preview_lines: int = 999,
    ) -> None:
        self.console = console or Console()
        self.theme = theme
        self.markdown_lexer = markdown_lexer
        self.syntax_theme = syntax_theme
        self.file_preview_lines = file_preview_lines

    # -------------------------
    # Public API
    # -------------------------

    def show_prompt(self, prompt_text: str, title: str = "Prompt", border_style: str = "blue") -> None:
        """
        Render a system or orchestrator prompt in a styled panel.
        """
        text = Text(prompt_text)
        text.highlight_regex(r"^#+.*$", style="bold magenta")
        text.highlight_regex(r"<[^>]+>", style="bold cyan")

        self.console.print(
            Panel(
                text,
                title=f"[bold green]{title}[/bold green]",
                border_style=border_style,
                padding=(1, 2),
            )
        )

    def render_stream_event(self, event: Mapping[str, Any]) -> None:
        """
        Render a single streamed event emitted by an agent.

        Expected shape:
            {"event_type": payload}
        """
        event_type, payload = self._extract_single_kv(event)

        self._divider(event_type)

        if event_type in {"PatchToolCallsMiddleware.before_agent", "model", "tools"}:
            for msg in self._extract_messages(payload):
                self.render_message(msg)

            if event_type == "tools":
                self._render_files_from_payload(payload)

        else:
            # Unknown/middleware events: show payload in JSON form
            self._render_system_payload(payload)

    def render_final_output(self, result: Mapping[str, Any]) -> None:
        """
        Render the final output returned by agent.invoke(...).

        Expected shape:
            {"messages": [...], "files": {...}, ...}
        """
        self._divider("FINAL OUTPUT")

        for msg in self._extract_messages(result):
            self.render_message(msg)

        files = self._get_payload_value(result, "files", default={}) or {}
        if isinstance(files, Mapping) and files:
            self._divider("FILES")
            for path, meta in files.items():
                self._render_file_meta(str(path), meta)

    def render_message(self, message: Any) -> None:
        """
        Render a single LangChain-style message or compatible object.
        """
        cls_name = message.__class__.__name__

        # Support common LangChain message class names
        if cls_name == "HumanMessage":
            self._render_text_panel(
                text=self._format_message_content(message),
                title=self.theme.user_title,
                border_style=self.theme.user_style,
            )
            return

        if cls_name == "AIMessage":
            self._render_text_panel(
                text=self._format_message_content(message) or "",
                title=self.theme.assistant_title,
                border_style=self.theme.assistant_style,
            )
            self._render_tool_calls_from_message(message)
            return

        if cls_name == "ToolMessage":
            self._render_tool_output_message(message)
            return

        # Fallback: render whatever we can
        self._render_text_panel(
            text=self._format_message_content(message),
            title=cls_name,
            border_style="white",
        )

    # -------------------------
    # Message formatting
    # -------------------------

    def _format_message_content(self, message: Any) -> str:
        """
        Extract and render message.content robustly. Supports:
        - Plain strings
        - List-of-blocks with {"type": "text"} / {"type": "tool_use"}
        - Any other object via str(...)
        """
        content = getattr(message, "content", "")

        parts: List[str] = []
        tool_calls_from_content = False

        if isinstance(content, str):
            parts.append(content)

        elif isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    parts.append(str(item))
                    continue

                item_type = item.get("type")
                if item_type == "text":
                    parts.append(str(item.get("text", "")))
                elif item_type in {"tool_use", "tool_call"}:
                    tool_calls_from_content = True
                    name = item.get("name", "unknown_tool")
                    tool_input = item.get("input", item.get("args", {}))
                    call_id = item.get("id", "N/A")
                    parts.append(f"[{self.theme.tool_call_title}] {name}")
                    parts.append(json.dumps(tool_input, indent=2, ensure_ascii=False))
                    parts.append(f"id: {call_id}")
                else:
                    parts.append(str(item))

        else:
            parts.append(str(content))

        # If tool calls were not embedded in content blocks, also check tool_calls attribute
        if not tool_calls_from_content:
            self._append_tool_calls_attribute(parts, message)

        return "\n".join(p for p in parts if p is not None and p != "")

    def _append_tool_calls_attribute(self, parts: List[str], message: Any) -> None:
        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls:
            return

        # tool_calls usually: [{"name": ..., "args": ..., "id": ...}, ...]
        if isinstance(tool_calls, Sequence):
            for call in tool_calls:
                if not isinstance(call, Mapping):
                    continue
                parts.append(f"[{self.theme.tool_call_title}] {call.get('name', 'unknown_tool')}")
                parts.append(json.dumps(call.get("args", {}), indent=2, ensure_ascii=False))
                parts.append(f"id: {call.get('id', 'N/A')}")

    def _render_tool_calls_from_message(self, message: Any) -> None:
        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls or not isinstance(tool_calls, Sequence):
            return

        for call in tool_calls:
            if not isinstance(call, Mapping):
                continue
            name = str(call.get("name", "unknown_tool"))
            args = call.get("args", {})
            call_id = call.get("id", "N/A")

            self._render_json_panel(
                data={"name": name, "args": args, "id": call_id},
                title=f"{self.theme.tool_call_title} — {name}",
                border_style=self.theme.tool_call_style,
            )

    def _render_tool_output_message(self, message: Any) -> None:
        content = getattr(message, "content", "")

        # Tool outputs are often JSON strings; parse if possible.
        if isinstance(content, str):
            parsed = self._try_parse_json(content)
            if parsed is not None:
                self._render_json_panel(
                    data=parsed,
                    title=self.theme.tool_output_title,
                    border_style=self.theme.tool_output_style,
                )
                return

        self._render_text_panel(
            text=str(content),
            title=self.theme.tool_output_title,
            border_style=self.theme.tool_output_style,
        )

    # -------------------------
    # Stream payload helpers
    # -------------------------

    def _extract_messages(self, payload: Any) -> List[Any]:
        """
        Extract 'messages' from dict-like payloads; returns an empty list if missing.
        Normalizes singleton -> list.
        """
        payload = self._unwrap_overwrite(payload)

        messages = self._get_payload_value(payload, "messages", default=[])
        messages = self._unwrap_overwrite(messages)

        if messages is None:
            return []
        if isinstance(messages, (list, tuple)):
            return list(messages)
        return [messages]

    def _render_files_from_payload(self, payload: Any) -> None:
        payload = self._unwrap_overwrite(payload)
        files = self._get_payload_value(payload, "files", default={}) or {}
        if not isinstance(files, Mapping):
            return
        for path, meta in files.items():
            self._render_file_meta(str(path), meta)

    def _render_file_meta(self, path: str, meta: Any) -> None:
        meta = meta or {}
        if not isinstance(meta, Mapping):
            meta = {"meta": str(meta)}

        preview = meta.get("content", [])
        if isinstance(preview, list):
            preview = preview[: self.file_preview_lines]
        else:
            preview = str(preview)

        self._render_json_panel(
            data={
                "path": path,
                "created_at": meta.get("created_at"),
                "modified_at": meta.get("modified_at"),
                "preview": preview,
            },
            title=f"{self.theme.file_title} — {path}",
            border_style=self.theme.file_style,
        )

    def _render_system_payload(self, payload: Any) -> None:
        payload = self._unwrap_overwrite(payload)

        # Prefer JSON panel for dict/list payloads
        if isinstance(payload, (dict, list)):
            self._render_json_panel(payload, self.theme.system_title, self.theme.system_style)
        else:
            self._render_text_panel(str(payload), self.theme.system_title, self.theme.system_style)

    # -------------------------
    # Low-level rendering
    # -------------------------

    def _divider(self, label: str = "") -> None:
        self.console.print(Rule(label, style=self.theme.divider_style))

    def _render_text_panel(self, text: str, title: str, border_style: str) -> None:
        syntax = Syntax(
            text or "",
            lexer=self.markdown_lexer,
            theme=self.syntax_theme,
            word_wrap=True,
        )
        self.console.print(
            Panel(
                syntax,
                title=title,
                border_style=border_style,
                padding=(1, 2),
            )
        )

    def _render_json_panel(self, data: Any, title: str, border_style: str) -> None:
        self.console.print(
            Panel(
                JSON.from_data(data, indent=2),
                title=title,
                border_style=border_style,
                padding=(1, 1),
            )
        )

    # -------------------------
    # Utilities
    # -------------------------

    @staticmethod
    def _extract_single_kv(mapping: Mapping[str, Any]) -> Tuple[str, Any]:
        if not mapping:
            raise ValueError("Event payload is empty.")
        if len(mapping) != 1:
            # Keep deterministic behavior, but avoid silent misrender
            raise ValueError(f"Expected exactly 1 top-level key in event, got {len(mapping)}.")
        return next(iter(mapping.items()))

    @staticmethod
    def _try_parse_json(text: str) -> Optional[Any]:
        try:
            return json.loads(text)
        except Exception:
            return None

    @staticmethod
    def _unwrap_overwrite(value: Any) -> Any:
        """
        Unwrap LangGraph Overwrite wrapper without requiring a direct import.
        """
        if value is None:
            return None
        # Common pattern: Overwrite(value=<payload>)
        if getattr(value, "__class__", None) and value.__class__.__name__ == "Overwrite":
            return getattr(value, "value", value)
        return value

    @staticmethod
    def _get_payload_value(payload: Any, key: str, default: Any = None) -> Any:
        payload = RichAgentRenderer._unwrap_overwrite(payload)
        if isinstance(payload, Mapping):
            return payload.get(key, default)
        return getattr(payload, key, default)


# -----------------------------
# Convenience functions
# -----------------------------

_DEFAULT_RENDERER = RichAgentRenderer()

_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialized RichAgentRenderer for rendering LangChain agent events and outputs."),
        title="STEP 1: Initialization",
        border_style="purple",
        padding=(1, 2),
    )
)

#%%

_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize your environment by loading .env variables."),
        title="STEP 2: Initialize Environment",
        border_style="purple",
        padding=(1, 2),
    )
)
import os
from typing import Any
from dotenv import load_dotenv

load_dotenv(".env", override=True)

# %%
_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize tools and affiliated resources."),
        title="STEP 3: Initialize Tools",
        border_style="purple",
        padding=(1, 2),
    )
)
from pathlib import Path
from langchain.tools import tool
from langgraph.types import Overwrite

from pathlib import Path

WORKSPACE_ROOT = Path("./workspace").resolve()


def resolve_workspace_path(virtual_path: str) -> Path:
    """
    Resolve a virtual workspace path into a real filesystem path.

    Accepts:
    - /workspace
    - /workspace/
    - /workspace/relative/path

    Rejects:
    - Any path outside the workspace namespace
    - Any path attempting directory traversal
    """

    if virtual_path == "/workspace":
        return WORKSPACE_ROOT

    if virtual_path.startswith("/workspace/"):
        relative = virtual_path[len("/workspace/") :]
        real_path = (WORKSPACE_ROOT / relative).resolve()
    else:
        raise ValueError(f"Invalid workspace path: {virtual_path}")

    # Enforce sandboxing
    if not str(real_path).startswith(str(WORKSPACE_ROOT)):
        raise ValueError(f"Path traversal detected: {virtual_path}")

    return real_path


def safe_fix_zip_filename(name: str) -> str:
    """
    Attempt to fix garbled ZIP filenames produced by legacy tools.
    Never raises UnicodeEncodeError.
    """
    try:
        raw = name.encode("latin1")  # latin1 is always reversible
    except Exception:
        return name

    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue

    return name


#%%
_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize unzip tool."),
        title="STEP 3: Initialize Tools",
        border_style="purple",
        padding=(1, 2),
    )
)
import zipfile


@tool(parse_docstring=True)
def unzip_workspace_file(virtual_zip_path: str) -> dict:
    """
    Unzip a ZIP archive located inside the workspace.

    This preprocessing function extracts the contents of a ZIP file referenced
    by a virtual workspace path. The archive is unpacked into a directory with
    the same base name as the ZIP file, located in the same workspace directory.

    The function operates strictly within the workspace sandbox:
    - Input paths are virtual (e.g. `/workspace/foo.zip`)
    - Execution is performed on resolved real paths
    - Output paths are returned in virtual-path form for agent consumption

    Typical agent usage:
    - Call this when a ZIP file is detected during workspace inspection
    - Follow with a tree-view operation on the extracted directory

    Args:
        virtual_zip_path: Virtual path to a ZIP file inside the workspace
            (for example `/workspace/datasets/images.zip`). PATH MUST START WITH `/workspace`.

    Returns:
        A dictionary containing:
        - status: Execution status string
        - zip: The input virtual ZIP path
        - extracted_to: Virtual path of the extracted directory
        - num_files: Number of files listed in the ZIP archive

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        ValueError: If the provided path does not point to a ZIP archive.
    """

    # zip_path = resolve_workspace_path(virtual_zip_path)

    # if not zip_path.exists():
    #     raise FileNotFoundError(zip_path)

    # if zip_path.suffix.lower() != ".zip":
    #     raise ValueError("Provided file is not a zip archive")

    # output_dir = zip_path.with_suffix("")
    # output_dir.mkdir(parents=True, exist_ok=True)

    # with zipfile.ZipFile(zip_path, "r") as zf:
    #     zf.extractall(output_dir)

    # return {
    #     "status": "ok",
    #     "zip": virtual_zip_path,
    #     "extracted_to": f"/workspace/{output_dir.name}",
    #     "num_files": len(zf.namelist()),
    # }

    zip_path = resolve_workspace_path(virtual_zip_path)

    if not zip_path.exists():
        raise FileNotFoundError(zip_path)

    if zip_path.suffix.lower() != ".zip":
        raise ValueError("Provided file is not a zip archive")

    output_dir = zip_path.with_suffix("")
    output_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        for info in infos:
            info.filename = safe_fix_zip_filename(info.filename)
            zf.extract(info, output_dir)

    return {
        "status": "ok",
        "zip": virtual_zip_path,
        "extracted_to": f"/workspace/{output_dir.name}",
        "num_files": len(infos),
    }


# %%
_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize tree view tool."),
        title="STEP 3: Initialize Tools",
        border_style="purple",
        padding=(1, 2),
    )
)
@tool(parse_docstring=True)
def tree_view_workspace(
    virtual_path: str,
    max_depth: int = 4,
    max_entries: int = 200,
) -> dict:
    """
    Generate a hierarchical tree view of a workspace directory.

    This preprocessing function inspects the directory structure rooted at a
    given virtual workspace path and produces a readable tree representation.
    It is designed for lightweight structural understanding rather than full
    content analysis.

    The function supports depth and entry limits to prevent excessive output
    and is suitable for agent-driven exploration and reporting.

    Typical agent usage:
    - Inspect workspace contents before deciding on further preprocessing
    - Summarize directory layout in reports such as `/final_report.md`
    - Validate results of prior operations such as unzip or file generation

    Args:
        virtual_path: Virtual workspace path to inspect, such as `/workspace`
            or `/workspace/data` PATH MUST START WITH `/workspace`.
        max_depth: Maximum directory depth to traverse. The default value limits
            traversal to a small number of levels to avoid excessive output.
        max_entries: Maximum total number of files or directories to include
            in the output. The default value prevents large directories from
            producing oversized results.

    Returns:
        A dictionary containing:
        - root: The inspected virtual path
        - max_depth: The depth limit used during traversal
        - entries: Number of directory entries included
        - tree: A newline-separated string representing the directory tree
        - truncated: Whether traversal stopped early due to entry limits

    Raises:
        FileNotFoundError: If the target path does not exist.
    """

    root = resolve_workspace_path(virtual_path)

    if not root.exists():
        raise FileNotFoundError(root)

    lines = []
    count = 0

    def walk(path: Path, prefix: str = "", depth: int = 0):
        nonlocal count
        if depth > max_depth or count >= max_entries:
            return

        for p in sorted(path.iterdir()):
            if count >= max_entries:
                return

            lines.append(f"{prefix}{p.name}")
            count += 1

            if p.is_dir():
                walk(p, prefix + "  ", depth + 1)

    walk(root)

    return {
        "root": virtual_path,
        "max_depth": max_depth,
        "entries": count,
        "tree": "\n".join(lines),
        "truncated": count >= max_entries,
    }


# %%

_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize PDF reader tool."),
        title="STEP 3: Initialize Tools",
        border_style="purple",
        padding=(1, 2),
    )
)
@tool(parse_docstring=True)
def pdf_reader(virtual_pdf_path: str, num_pages: int = 5) -> dict:
    """
    Read the first N pages of a PDF file located inside the workspace.

    This preprocessing function extracts text from the first N pages of a PDF
    file referenced by a virtual workspace path.

    The function operates strictly within the workspace sandbox:
    - Input paths are virtual (e.g. `/workspace/document.pdf`)
    - Execution is performed on resolved real paths
    - Output paths are returned in virtual-path form for agent consumption

    Typical agent usage:
    - Call this when a PDF file is detected during workspace inspection
    - Follow with further operations based on the extracted text

    Args:
        virtual_pdf_path: Virtual path to a PDF file inside the workspace
            (for example `/workspace/document.pdf`). PATH MUST START WITH `/workspace`.
        num_pages: Number of pages to read from the start of the PDF.
    
    Returns:
        A dictionary containing:
        - status: Execution status string
        - pdf: The input virtual PDF path
        - content: Extracted text from the first N pages of the PDF
    
    Raises:
        FileNotFoundError: If the PDF file does not exist.
        ValueError: If the provided path does not point to a PDF file.
    """
    from pypdf import PdfReader

    pdf_path = resolve_workspace_path(virtual_pdf_path)

    if not pdf_path.exists():
        return {
            "status": "error",
            "content": f"File not found: {virtual_pdf_path}"
        }

    if pdf_path.suffix.lower() != ".pdf":
        raise ValueError("Provided file is not a PDF file")

    reader = PdfReader(str(pdf_path))
    content = []

    for i, page in enumerate(reader.pages):
        if i >= num_pages:
            break
        content.append(page.extract_text())

    return {
        "status": "ok",
        "pdf": virtual_pdf_path,
        "content": "\n".join(content),
    }
# %%
all_tools = [
    tree_view_workspace,
    unzip_workspace_file,
    pdf_reader,
]
# %%
_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize Prompts."),
        title="STEP 4: Initialize Prompts",
        border_style="purple",
        padding=(1, 2),
    )
)
ORCHESTRATOR_SYSTEM_PROMPT = """
Your job is to fullfill user's request step-by-step

# Rule of using different storage

1. the /final_report.md /plan.md /todo-list.md /file-summary.md /plan-hierarchical.md etc. all the files as a general perspective understanding or plan must be stored in the / root level
2. all the input files, are stored in the /workspace and therefore user's reference to user-provided files are located here
3. If the plan involves reading many resources, you should use the root-level storage as temporary storage for your analysis results, summaries, notes, etc., and use the /workspace for user-provided files only.
4. If intended to write enormous files, you should complete part-by-part and store them in the / root level storage, and combine them all together at the end to form the final output file. For example, if you were to write a report including 8 chapters, you should write chapter 1 to chapter 8 separately as /chapter_1.md, /chapter_2.md, ..., /chapter_8.md, and then combine them all together to form the final /final_report.md at the end, to ensure each part's comprehensiveness.

# IMPORTANT NOTE

1. NEVER try to create or run ANY executable files, scripts, or code that can be executed in the system, you are not allowed to run any code that can be executed in the system.
2. Do not delegate any file operations to sub-agents, all file operations must be handled by you directly using the provided tools. You can use script for batch operation if needed.
"""
_DEFAULT_RENDERER.show_prompt(ORCHESTRATOR_SYSTEM_PROMPT, title="Orchestrator Prompt")
# %%
_DEFAULT_RENDERER.console.print(
    Panel(
        Text("Initialize Deep Agent."),
        title="STEP 5: Initialize Deep Agent",
        border_style="purple",
        padding=(1, 2),
    )
)
from deepagents import create_deep_agent
from langchain.chat_models import init_chat_model
from langchain_openai import ChatOpenAI

# Default model; replace with any LangChain-compatible chat model
# model = init_chat_model(model="anthropic:claude-sonnet-4-5-20250929", temperature=0.0)


def build_model():
    """Pick the default LLM based on environment-driven provider selection."""
    provider = (os.getenv("DEEP_SCHOLAR_LLM_PROVIDER") or "iflow").lower()

    if provider == "deepseek":
        return ChatOpenAI(
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            temperature=float(os.getenv("DEEPSEEK_TEMPERATURE", "0.2")),
        )

    if provider == "llama":
        return ChatOpenAI(
            base_url=os.getenv("LLAMA_BASE_URL", "http://localhost:11434/v1"),
            api_key=os.getenv("LLAMA_API_KEY"),
            model=os.getenv("LLAMA_MODEL", "llama3"),
            temperature=float(os.getenv("LLAMA_TEMPERATURE", "0.2")),
        )

    # Default: IFlow (qwen3-max)
    return ChatOpenAI(
        base_url=os.getenv("IFLOW_BASE_URL", "https://apis.iflow.cn/v1"),
        api_key=os.getenv("IFLOW_API_KEY"),
        model=os.getenv("IFLOW_MODEL", "qwen3-max"),
        temperature=float(os.getenv("IFLOW_TEMPERATURE", "0.2")),
    )


model = build_model()

from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from langgraph.store.memory import InMemoryStore
from deepagents.backends import FilesystemBackend


composite_backend = lambda rt: CompositeBackend(
    default=StateBackend(rt),
    routes={
        "/workspace/": FilesystemBackend(root_dir="./workspace", virtual_mode=True),
    },
)

agent = create_deep_agent(
    model=model,
    tools=all_tools,
    system_prompt=ORCHESTRATOR_SYSTEM_PROMPT,
    subagents=[],
    backend=composite_backend,
)

# %%
request_message = {
    "messages": [
        {
            "role": "user",
            "content": "Write me a /final_report.md based on the files from the zip file inside the /workspace, write the summary report in pure Chinese, make it extremly long and detailed, use as many as references from Chinese Commnunist Party history or Communism Theory as possible, make it official and academic style, targeting as a report for the central standing committee of the Communist Party of China.",
        }
    ],
}

# %%
if __name__ == "__main__":
    for event in agent.stream(request_message):
        render_stream_event(event)
# %%
if __name__ == "__main__":
    example_result = agent.invoke(request_message)
# %%
if __name__ == "__main__":
    _DEFAULT_RENDERER.render_final_output(example_result)
    print(example_result['files'])
# %%
