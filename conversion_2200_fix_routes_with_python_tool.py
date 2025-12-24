# 【WARNING！】提供 Python tool 很危险！只能临时测试，不能作为真正工程代码

# %%

import os
from typing import Any
from dotenv import load_dotenv

load_dotenv(".env", override=True)

# %% [markdown]
# # Local Storage Deepagent (Tree View)
#
# This notebook-style script mirrors the research quickstart format, but for the file-oriented deep agent. It keeps planning/synthesis in root-level internal artifacts and delegates external inspection to a tree-view sub-agent.

# %% [markdown]
# ## Task-Specific Tools
#
# We only expose the `tree_view` inspection tool to the external sub-agent. The orchestrator should delegate to it rather than calling filesystem tools directly.
from pathlib import Path
from langchain.tools import tool
from langgraph.types import Overwrite

from pathlib import Path

WORKSPACE_ROOT = Path("./workspace").resolve()


import ast
import io
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from langchain.tools import tool

# ---------- 安全策略配置 ----------

FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "shutil",
    "ctypes",
    "multiprocessing",
    "asyncio",
}

# FORBIDDEN_BUILTINS = {
#     "exec",
#     "eval",
#     "compile",
#     "open",   # 强制用 pathlib
#     "__import__",
# }

# 允许 Agent import 的模块
ALLOWED_MODULES = {"os", "json", "pathlib", "csv", "re", "math"}

# 仅禁掉危险的 builtins
FORBIDDEN_BUILTINS = {"exec", "eval"}  # ⚠️ 注意不要禁 __import__

# ---------- AST 安全检查 ----------

class SecurityVisitor(ast.NodeVisitor):
    # def visit_Import(self, node):
    #     for alias in node.names:
    #         if alias.name.split(".")[0] in FORBIDDEN_MODULES:
    #             raise ValueError(f"Forbidden import: {alias.name}")
    #     self.generic_visit(node)

    # def visit_ImportFrom(self, node):
    #     if node.module and node.module.split(".")[0] in FORBIDDEN_MODULES:
    #         raise ValueError(f"Forbidden import: {node.module}")
    #     self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name.split(".")[0] not in ALLOWED_MODULES:
                raise ValueError(f"Forbidden import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.module.split(".")[0] not in ALLOWED_MODULES:
            raise ValueError(f"Forbidden import: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node):
        # 禁止 os.system / subprocess.run 等
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"system", "popen", "run", "call"}:
                raise ValueError(f"Forbidden function call: {node.func.attr}")
        self.generic_visit(node)

# ---------- Tool 本体 ----------

@tool
def run_python_script(code: str) -> str:
    """
    Execute Python code in a restricted environment.
    - Relative paths only
    - No shell / subprocess
    - Cross-platform safe
    """

    # 1. AST 检查
    try:
        tree = ast.parse(code)
        SecurityVisitor().visit(tree)
    except Exception as e:
        return f"❌ Security check failed:\n{e}"

    # 2. 受控 builtins
    safe_builtins = {
        k: __builtins__[k]
        for k in __builtins__
        if k not in FORBIDDEN_BUILTINS
    }

    # 3. 受控 globals
    safe_globals = {
        "__builtins__": safe_builtins,
        "Path": Path,
    }

    stdout = io.StringIO()
    stderr = io.StringIO()

    # 4. 执行
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exec(compile(tree, filename="<agent-script>", mode="exec"), safe_globals, {})
    except Exception as e:
        return f"❌ Execution error:\n{e}"

    # 5. 返回结果
    out = stdout.getvalue()
    err = stderr.getvalue()

    if err:
        return f"⚠️ STDERR:\n{err}\n\nSTDOUT:\n{out}"

    return f"✅ Execution finished.\n\n{out or '(no output)'}"





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
        # raw = name.encode("latin1")  # latin1 is always reversible
        raw = name.encode("cp437")  # latin1 is always reversible
    except Exception:
        return name

    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue

    return name


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
#%%

# @tool(parse_docstring=True)
# def get_json_headers(virtual_json_path: str) -> dict:
#     """
#     Get the root-level keys of a JSON file located inside the workspace.

#     This preprocessing function reads a JSON file referenced
#     by a virtual workspace path and returns its root-level keys.

#     The function operates strictly within the workspace sandbox:
#     - Input paths are virtual (e.g. `/workspace/data.json`)
#     - Execution is performed on resolved real paths
#     - Output paths are returned in virtual-path form for agent consumption

#     Typical agent usage:
#     - Call this when a JSON file is detected during workspace inspection
#     - Follow with further operations based on the structure of the JSON

#     Args:
#         virtual_json_path: Virtual path to a JSON file inside the workspace
#             (for example `/workspace/data.json`). PATH MUST START WITH `/workspace`.
            
#     Returns:
#         A dictionary containing:
#         - status: Execution status string
#         - json: The input virtual JSON path
#         - keys: List of root-level keys in the JSON file
        
#     Raises:
#         FileNotFoundError: If the JSON file does not exist.
#         ValueError: If the provided path does not point to a JSON file.
#     """

#     json_path = resolve_workspace_path(virtual_json_path)

#     if not json_path.exists():
#         raise FileNotFoundError(json_path)

#     if json_path.suffix.lower() != ".json":
#         raise ValueError("Provided file is not a JSON file")

#     with open(json_path, "r", encoding="utf-8") as f:
#         data = json.load(f)

#     if not isinstance(data, dict):
#         raise ValueError("JSON file does not contain a root-level object")

#     return {
#         "status": "ok",
#         "json": virtual_json_path,
#         "keys": list(data.keys()),
#     }

# #%%
# @tool(parse_docstring=True)
# def read_json_content(virtual_json_path: str, keys: list) -> dict:
#     """
#     Read specific keys from a JSON file located inside the workspace.

#     This preprocessing function reads a JSON file referenced
#     by a virtual workspace path and returns the values of specified keys.

#     The function operates strictly within the workspace sandbox:
#     - Input paths are virtual (e.g. `/workspace/data.json`)
#     - Execution is performed on resolved real paths
#     - Output paths are returned in virtual-path form for agent consumption

#     Typical agent usage:
#     - Call this when a JSON file is detected during workspace inspection
#     - Follow with further operations based on the content of the JSON

#     Args:
#         virtual_json_path: Virtual path to a JSON file inside the workspace
#             (for example `/workspace/data.json`). PATH MUST START WITH `/workspace`.
#         keys: List of keys to read from the JSON file.
        
#     Returns:
#         A dictionary containing:
#         - status: Execution status string
#         - json: The input virtual JSON path
#         - content: Dictionary of requested keys and their values
        
#     Raises:
#         FileNotFoundError: If the JSON file does not exist.
#         ValueError: If the provided path does not point to a JSON file.
#     """
#     json_path = resolve_workspace_path(virtual_json_path)

#     if not json_path.exists():
#         raise FileNotFoundError(json_path)

#     if json_path.suffix.lower() != ".json":
#         raise ValueError("Provided file is not a JSON file")

#     with open(json_path, "r", encoding="utf-8") as f:
#         data = json.load(f)

#     if not isinstance(data, dict):
#         raise ValueError("JSON file does not contain a root-level object")

#     content = {key: data.get(key) for key in keys}

#     return {
#         "status": "ok",
#         "json": virtual_json_path,
#         "content": content,
#     }


# @tool(parse_docstring=True)
# def create_json_content(virtual_json_path: str, content: dict) -> dict:
#     """
#     Create a new JSON file with specified content inside the workspace.

#     This preprocessing function creates a new JSON file at a virtual
#     workspace path with the provided content.

#     The function operates strictly within the workspace sandbox:
#     - Input paths are virtual (e.g. `/workspace/data.json`)
#     - Execution is performed on resolved real paths
#     - Output paths are returned in virtual-path form for agent consumption

#     Typical agent usage:
#     - Call this to create new JSON files in the workspace

#     Args:
#         virtual_json_path: Virtual path to create a JSON file inside the workspace
#             (for example `/workspace/data.json`). PATH MUST START WITH `/workspace`.
#         content: Dictionary of keys and values to write to the JSON file.
        
#     Returns:
#         A dictionary containing:
#         - status: Execution status string
#         - json: The input virtual JSON path
    
    
#     """
#     json_path = resolve_workspace_path(virtual_json_path)
#     # create new file
    
#     if json_path.suffix.lower() != ".json":
#         raise ValueError("Provided file is not a JSON file")

#     with open(json_path, "w", encoding="utf-8") as f:
#         json.dump(content, f, indent=2)

#     return {
#         "status": "ok",
#         "json": virtual_json_path,
#     }


# @tool(parse_docstring=True)
# def edit_json_content(virtual_json_path: str, updates: dict) -> dict:
#     """
#     Edit specific keys in a JSON file located inside the workspace.

#     This preprocessing function updates specific keys in a JSON file referenced
#     by a virtual workspace path.

#     The function operates strictly within the workspace sandbox:
#     - Input paths are virtual (e.g. `/workspace/data.json`)
#     - Execution is performed on resolved real paths
#     - Output paths are returned in virtual-path form for agent consumption

#     Typical agent usage:
#     - Call this to update specific information in a JSON file in the workspace

#     Args:
#         virtual_json_path: Virtual path to a JSON file inside the workspace
#             (for example `/workspace/data.json`). PATH MUST START WITH `/workspace`.
#         updates: Dictionary of keys and their new values to update in the JSON file.
        
#     Returns:
#         A dictionary containing:
#         - status: Execution status string
#         - json: The input virtual JSON path
        
#     Raises:
#         FileNotFoundError: If the JSON file does not exist.
#         ValueError: If the provided path does not point to a JSON file.
#     """
#     json_path = resolve_workspace_path(virtual_json_path)

#     if not json_path.exists():
#         raise FileNotFoundError(json_path)

#     if json_path.suffix.lower() != ".json":
#         raise ValueError("Provided file is not a JSON file")

#     with open(json_path, "r", encoding="utf-8") as f:
#         data = json.load(f)

#     if not isinstance(data, dict):
#         raise ValueError("JSON file does not contain a root-level object")

#     data.update(updates)

#     with open(json_path, "w", encoding="utf-8") as f:
#         json.dump(data, f, indent=2)

#     return {
#         "status": "ok",
#         "json": virtual_json_path,
#     }

import shutil
import time

@tool(parse_docstring=True)
def move_workspace_file(source_path: str, destination_path: str) -> dict:
    """
    Move or rename a file/directory within the workspace.

    This tool allows the agent to organize files by moving them into specific
    folders or renaming them. It automatically creates any missing parent
    directories for the destination path.

    Args:
        source_path: The virtual path of the file to move (e.g., "/workspace/data.txt")
        destination_path: The target virtual path (e.g., "/workspace/documents/data.txt")

    Returns:
        A dictionary with the status and new location.
    """
    src_real = resolve_workspace_path(source_path)
    dst_real = resolve_workspace_path(destination_path)

    if not src_real.exists():
        raise FileNotFoundError(f"Source not found: {source_path}")

    if dst_real.exists():
        raise FileExistsError(f"Destination already exists: {destination_path}")

    # Ensure destination directory exists
    dst_real.parent.mkdir(parents=True, exist_ok=True)

    shutil.move(str(src_real), str(dst_real))

    return {
        "status": "moved",
        "from": source_path,
        "to": destination_path
    }

@tool(parse_docstring=True)
def delete_workspace_file(virtual_path: str) -> dict:
    """
    Safely delete a file by moving it to a .trash folder.

    Instead of permanently deleting files, this tool moves them to a hidden
    '/workspace/.trash' directory. This provides a safety mechanism allowing
    recovery if the agent makes a mistake.

    Args:
        virtual_path: The virtual path of the file to delete (e.g., "/workspace/junk.tmp")

    Returns:
        A dictionary with the status and trash location.
    """
    target_real = resolve_workspace_path(virtual_path)

    if not target_real.exists():
        raise FileNotFoundError(f"File not found: {virtual_path}")

    # Define trash directory
    trash_dir = WORKSPACE_ROOT / ".trash"
    trash_dir.mkdir(exist_ok=True)

    # Create a unique name to prevent overwriting in trash
    # e.g., filename_1708456.txt
    timestamp = int(time.time())
    trash_name = f"{target_real.stem}_{timestamp}{target_real.suffix}"
    trash_path = trash_dir / trash_name

    shutil.move(str(target_real), str(trash_path))

    return {
        "status": "deleted (moved to trash)",
        "original_path": virtual_path,
        "trash_path": f"/workspace/.trash/{trash_name}"
    }

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
            "message": f"File not found: {virtual_pdf_path}"
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
    run_python_script,  # 新增 Python tool
    tree_view_workspace,
    unzip_workspace_file,
    delete_workspace_file,
    move_workspace_file,
    pdf_reader,
]

# json_tools = [
#     get_json_headers,
#     read_json_content,
#     create_json_content,
#     edit_json_content,
# ]

# %% [markdown]
# ## Prompt Helpers
#
# Minimal helpers to display prompts and messages (inspired by the research quickstart utils).

# %%
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def show_prompt(prompt_text: str, title: str = "Prompt", border_style: str = "blue"):
    """Display a prompt with simple highlighting."""
    formatted_text = Text(prompt_text)
    formatted_text.highlight_regex(r"<[^>]+>", style="bold blue")
    formatted_text.highlight_regex(r"##[^#\n]+", style="bold magenta")
    formatted_text.highlight_regex(r"###[^#\n]+", style="bold cyan")
    console.print(
        Panel(
            formatted_text,
            title=f"[bold green]{title}[/bold green]",
            border_style=border_style,
            padding=(1, 2),
        )
    )


def format_message_content(message):
    """Render message content, including tool calls when present."""
    parts = []
    tool_calls_processed = False

    if isinstance(message.content, str):
        parts.append(message.content)
    elif isinstance(message.content, list):
        for item in message.content:
            if item.get("type") == "text":
                parts.append(item["text"])
            elif item.get("type") == "tool_use":
                parts.append(f"\n🔧 Tool Call: {item['name']}")
                parts.append(f"   Args: {json.dumps(item['input'], indent=2)}")
                parts.append(f"   ID: {item.get('id', 'N/A')}")
                tool_calls_processed = True
    else:
        parts.append(str(message.content))

    if (
        not tool_calls_processed
        and hasattr(message, "tool_calls")
        and message.tool_calls
    ):
        for tool_call in message.tool_calls:
            parts.append(f"\n🔧 Tool Call: {tool_call['name']}")
            parts.append(f"   Args: {json.dumps(tool_call['args'], indent=2)}")
            parts.append(f"   ID: {tool_call['id']}")

    return "\n".join(parts)


def _unwrap_overwrite(value: Any) -> Any:
    """Return the underlying value if wrapped in Overwrite."""
    return value.value if isinstance(value, Overwrite) else value


def _ensure_message_list(messages: Any) -> list:
    """
    Normalize message containers into a list.

    Handles LangGraph's Overwrite wrapper so stream payloads that replace
    message lists don't crash the renderer.
    """
    messages = _unwrap_overwrite(messages)

    if messages is None:
        return []

    if isinstance(messages, (list, tuple)):
        return list(messages)

    return [messages]


def _get_payload_value(payload: Any, key: str, default: Any = None) -> Any:
    """Fetch a key from dict-like payloads or fall back to attributes."""
    payload = _unwrap_overwrite(payload)
    if isinstance(payload, dict):
        return payload.get(key, default)
    return getattr(payload, key, default)


def _extract_messages(payload: Any) -> list:
    """Convenience wrapper to pull 'messages' out of stream payloads."""
    payload = _unwrap_overwrite(payload)
    return _ensure_message_list(_get_payload_value(payload, "messages", []))


def format_messages(messages):
    """Pretty-print a list of messages."""
    for m in _ensure_message_list(messages):
        msg_type = m.__class__.__name__.replace("Message", "")
        content = format_message_content(m)

        if msg_type == "Human":
            console.print(Panel(content, title="🧑 Human", border_style="blue"))
        elif msg_type == "Ai":
            console.print(Panel(content, title="🤖 Assistant", border_style="green"))
        elif msg_type == "Tool":
            console.print(Panel(content, title="🔧 Tool Output", border_style="yellow"))
        else:
            console.print(Panel(content, title=f"📝 {msg_type}", border_style="white"))


def format_message(m):
    """Pretty-print a list of messages."""
    msg_type = m.__class__.__name__.replace("Message", "")
    content = format_message_content(m)

    if msg_type == "Human":
        console.print(Panel(content, title="🧑 Human", border_style="blue"))
    elif msg_type == "Ai":
        console.print(Panel(content, title="🤖 Assistant", border_style="green"))
    elif msg_type == "Tool":
        console.print(Panel(content, title="🔧 Tool Output", border_style="yellow"))
    else:
        console.print(Panel(content, title=f"📝 {msg_type}", border_style="white"))


# %%
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.json import JSON
from rich.rule import Rule
from rich.text import Text

import json

console = Console()


THEME = {
    "user": ("🧑 User", "bold blue"),
    "assistant": ("🤖 Assistant", "bold green"),
    "tool_call": ("🔧 Tool Call", "bold magenta"),
    "tool_output": ("📦 Tool Output", "bold yellow"),
    "file": ("📝 File Artifact", "bold cyan"),
    "system": ("⚙️ System", "dim"),
    "divider": "dim white",
}


# %%
def show_prompt(prompt_text: str, title: str = "Prompt", border_style: str = "blue"):
    """
    Render a system or orchestrator prompt in a styled panel.
    """
    text = Text(prompt_text)
    text.highlight_regex(r"^#+.*$", style="bold magenta")
    text.highlight_regex(r"<[^>]+>", style="bold cyan")

    console.print(
        Panel(
            text,
            title=f"[bold green]{title}[/bold green]",
            border_style=border_style,
            padding=(1, 2),
        )
    )


# %%
def divider(label: str = ""):
    console.print(Rule(label, style=THEME["divider"]))


# %%
def render_text_block(text: str, title: str, style: str):
    syntax = Syntax(
        text,
        lexer="markdown",
        theme="monokai",
        word_wrap=True,
    )
    console.print(
        Panel(
            syntax,
            title=title,
            border_style=style,
            padding=(1, 2),
        )
    )


# %%
def render_json_block(data, title: str, style: str):
    console.print(
        Panel(
            JSON.from_data(data, indent=2),
            title=title,
            border_style=style,
            padding=(1, 1),
        )
    )


# %%
def render_langchain_message(message):
    """
    Render a single LangChain message with styling.
    """
    cls = message.__class__.__name__

    # 🧑 Human
    if cls == "HumanMessage":
        title, style = THEME["user"]
        render_text_block(message.content, title, style)

    # 🤖 Assistant
    elif cls == "AIMessage":
        title, style = THEME["assistant"]
        render_text_block(message.content or "", title, style)

        # Render embedded tool calls (if any)
        if hasattr(message, "tool_calls") and message.tool_calls:
            for call in message.tool_calls:
                render_json_block(
                    {
                        "name": call["name"],
                        "args": call["args"],
                        "id": call["id"],
                    },
                    f"{THEME['tool_call'][0]} — {call['name']}",
                    THEME["tool_call"][1],
                )

    # 📦 Tool output
    elif cls == "ToolMessage":
        title, style = THEME["tool_output"]
        try:
            render_json_block(json.loads(message.content), title, style)
        except Exception:
            render_text_block(message.content, title, style)


# %%
def render_stream_event(event: dict):
    """
    Render a single stream event emitted by DeepAgent.
    """
    # Each event has exactly one top-level key
    [(event_type, payload)] = event.items()

    divider(event_type)

    # 1️⃣ User injection
    if event_type == "PatchToolCallsMiddleware.before_agent":
        for msg in _extract_messages(payload):
            render_langchain_message(msg)

    # 2️⃣ LLM step
    elif event_type == "model":
        for msg in _extract_messages(payload):
            render_langchain_message(msg)

    # 3️⃣ Tool execution + file artifacts
    elif event_type == "tools":
        # Tool messages
        for msg in _extract_messages(payload):
            render_langchain_message(msg)

        # Files written / updated
        files = _get_payload_value(payload, "files", {}) or {}
        for path, meta in files.items():
            render_json_block(
                {
                    "path": path,
                    "created_at": meta.get("created_at"),
                    "modified_at": meta.get("modified_at"),
                    "preview": meta.get("content", [])[:8],
                },
                f"{THEME['file'][0]} {path}",
                THEME["file"][1],
            )

    # 4️⃣ System / summarization / other middleware
    else:
        clean_payload = payload.value if isinstance(payload, Overwrite) else payload
        render_json_block(clean_payload, THEME["system"][0], THEME["system"][1])


# %%
def render_final_output(result: dict):
    """
    Render the final output of agent.invoke(...)
    """
    divider("FINAL OUTPUT")

    # Messages
    for msg in _extract_messages(result):
        render_langchain_message(msg)

    # Files (artifacts)
    files = result.get("files", {})
    if files:
        divider("FILES")
        for path, meta in files.items():
            render_json_block(
                {
                    "path": path,
                    "created_at": meta.get("created_at"),
                    "modified_at": meta.get("modified_at"),
                    "preview": meta.get("content", [])[:],
                },
                f"{THEME['file'][0]} {path}",
                THEME["file"][1],
            )


# %% [markdown]
# ## Task-Specific Instructions
#
# Orchestrator prompt enforces internal vs external separation; sub-agent prompt restricts to tree inspection only.

# %%

# ORCHESTRATOR_SYSTEM_PROMPT = """
# Your job is to fullfill user's request step-by-step

# # Rule of using different storage

# 1. the /final_report.md /plan.md /todo-list.md /file-summary.md /plan-hierarchical.md etc. all the files as a general perspective understanding or plan must be stored in the / root level
# 2. all the input files, are stored in the /workspace and therefore user's reference to user-provided files are located here

# # IMPORTANT NOTE

# 1. **CROSS-PLATFORM COMPATIBILITY**: You are running in a Python environment that supports both Windows and Linux.
#    - **DO NOT write Bash scripts** (.sh) or Batch scripts (.bat) for file operations.
#    - **DO NOT** use commands like `ls`, `grep`, `cp` or bash variables like `${BASH_SOURCE[0]}`.
#    - If you need to perform batch operations (e.g., renaming 100 files), write and execute a **Python script** instead.
#    - Always use `os.path.join` or `pathlib` for path manipulation to ensure compatibility with Windows backslashes (`\`) and Linux forward slashes (`/`).

# 2. **Path Handling**:
#    - Files in the workspace are real files on the disk.
#    - Always use relative paths when writing python scripts (e.g., `./data/input.csv` instead of `/Users/name/...`).

# 3. Do not delegate any file operations to sub-agents, all file operations must be handled by you directly using the provided tools.
# """

# 【这个版本支持 Python tool】
ORCHESTRATOR_SYSTEM_PROMPT = """
Your job is to fulfill the user's request step-by-step.

You are encouraged to write Python scripts AND execute them using the provided tool
when it helps complete tasks more reliably or efficiently.

IMPORTANT:
- Sub-agents are DISABLED.
- You must perform all reasoning, scripting, and file operations yourself.

---

# File System Rules

1. Planning, summaries, and reports (e.g. /final_report.md, /plan.md, /todo-list.md)
   must be stored at the ROOT level.

2. User-provided input files are located in ./workspace/.
   Always use relative paths when accessing them.

---

# Script Execution Rules (STRICT)

1. **Python only**
   - Do NOT write or rely on Bash, Batch, or PowerShell scripts.

2. **Relative paths only**
   - Never use absolute paths (e.g. /workspace, C:\, /Users).
   - Always use pathlib or os.path with relative paths.

3. **No shell or subprocess**
   - Do not attempt to run shell commands or external programs.

4. **Explicit execution**
   - When execution is needed, call the tool `run_python_script`.
   - Do not claim code was executed unless you actually used the tool.

5. **Deterministic behavior**
   - Prefer scripts that are deterministic and reproducible.

---

Think carefully before executing code.
If unsure, explain your plan first, then execute.
"""


SUBAGENT_DELEGATION_INSTRUCTIONS = """
# Sub-Agent Delegation Policy — Local Storage DeepAgent

Your role is to coordinate task execution by delegating clearly scoped work
to sub-agents when—and only when—delegation provides a concrete benefit.

You are an orchestrator, not a worker.
Do NOT perform exploratory reasoning or filesystem inspection yourself.

## Default Delegation Strategy

**DEFAULT: Use ZERO sub-agents.**

The Local Storage DeepAgent is optimized for:
- Deterministic filesystem inspection
- ZIP preprocessing
- Tree structure summarization
- Structured report generation

These tasks SHOULD be executed directly by the main agent using tools.

Examples:
- "List files in workspace" → no sub-agent
- "Unzip archives and summarize contents" → no sub-agent
- "Generate /final_report.md from workspace" → no sub-agent

## When Delegation Is Allowed

**ONLY delegate when the task includes an explicit secondary reasoning domain
that is orthogonal to filesystem manipulation. Especially when encountering analytical tasks that involves the file's manipulations and file understanding or file re-organization etc.**

### Allowed Delegation Patterns

**Semantic or analytical interpretation** (1 sub-agent):
- "Analyze the project structure and infer its purpose"
- "Explain what this dataset is likely used for"
- "Assess risks or compliance issues from file contents"

In this case:
- The main agent handles ALL filesystem tools
- The sub-agent receives ONLY structured summaries or tree outputs
- The sub-agent MUST NOT call tools or access the filesystem

**Comparative reasoning over results** (1 sub-agent):
- "Compare two extracted directories"
- "Evaluate differences between workspace snapshots"

Again:
- Main agent gathers data
- Sub-agent reasons over provided summaries only

## Forbidden Delegation Patterns

The following are NOT valid reasons to create sub-agents:

- Inspecting directories
- Traversing file trees
- Detecting ZIP files
- Extracting archives
- Writing or updating files
- Generating `/final_report.md`

Do NOT delegate:
- "tree_view_workspace"
- "unzip_workspace_file"
- Any operation that touches `/workspace` or filesystem backends

## Delegation Principles

- **Bias strongly toward no delegation**
- **Never delegate tool usage**
- **Never delegate sandboxed I/O**
- **Sub-agents reason; the main agent acts**
- **If delegation does not reduce complexity, do not use it**

## Execution Limits

- At most **3 sub-agents per request**
- At most **3 parallel sub-agents per delegation round**
- Delegation occurs in a single round only

## Termination Rules

- Stop delegating once sufficient reasoning is obtained
- Do not iterate delegation to refine phrasing or style
- Prefer deterministic execution over speculative analysis
"""

FILE_UNIVERSAL_PROCESSOR_SYSTEM_PROMPT = """


# Rules of preprocessing files

You will need to do pre-processings on files inside the /workspace and generate the intermediate information about those files.


1. Your job is to convert files inside the /workspace:
2. Write the intermediate information into the /workspace/intermediate.json file, you will first create this json file if there isn't this file.
3. Use the original file path as the reference when writing into the /workspace/intermediate.json file, and provide converted text information, file type, summary as the value. for example
```json
{
  "/workspace/data.csv": {
    "file_type": "csv",
    "summary": "This is a CSV file containing sales data with columns for date, product, quantity, and price.",
    "content": "Date,Product,Quantity,Price\n2023-01-01,Widget A,10,9.99\n2023-01-02,Widget B,5,19.99\n..."
  },
  "/workspace/report.pdf": {
    "file_type": "pdf",
    "summary": "This PDF report provides an analysis of market trends in Q1 2023, including charts and key insights.",
    "content": "Market Trends Q1 2023\nThe first quarter of 2023 has seen significant shifts in consumer behavior..."
  },
  "/workspace/image.png": {
    "file_type": "image",
    "summary": "This image is a high-resolution photograph of a sunset over the mountains.",
    "content": "Image data cannot be directly represented as text, but it depicts a sunset over mountains with vibrant colors."
  }
}
```

"""
show_prompt(ORCHESTRATOR_SYSTEM_PROMPT, title="Orchestrator Prompt")
show_prompt(SUBAGENT_DELEGATION_INSTRUCTIONS, title="Sub-Agent Delegation Instructions")
show_prompt(
    FILE_UNIVERSAL_PROCESSOR_SYSTEM_PROMPT,
    title="File Universal Processor Agent Prompt",
    border_style="green",
)
# show_prompt(
#     FILE_PROCESSOR_SYSTEM_PROMPT,
#     title="External File Processor Prompt",
#     border_style="green",
# )


# %% [markdown]
# ## Create the Agent
#
# Build the orchestrator with built-in tools and the external sub-agent. Swap the model as needed.

# %%
from deepagents import create_deep_agent
from langchain.chat_models import init_chat_model
from langchain_openai import ChatOpenAI

# Default model; replace with any LangChain-compatible chat model
# model = init_chat_model(model="anthropic:claude-sonnet-4-5-20250929", temperature=0.0)


def build_model():
    """Pick the default LLM based on environment-driven provider selection."""
    provider = (os.getenv("DEEP_SCHOLAR_LLM_PROVIDER") or "iflow").lower()
    from langchain_core.callbacks import StdOutCallbackHandler

    if provider == "deepseek":
        return ChatOpenAI(
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            temperature=float(os.getenv("DEEPSEEK_TEMPERATURE", "0.2")),
            callbacks=[StdOutCallbackHandler()],  # 打印日志到 stdout
        )

    if provider == "llama":
        return ChatOpenAI(
            base_url=os.getenv("LLAMA_BASE_URL", "http://localhost:11434/v1"),
            api_key=os.getenv("LLAMA_API_KEY"),
            model=os.getenv("LLAMA_MODEL", "llama3"),
            temperature=float(os.getenv("LLAMA_TEMPERATURE", "0.2")),
            callbacks=[StdOutCallbackHandler()],  # 打印日志到 stdout
        )

    # Default: IFlow (qwen3-max)
    return ChatOpenAI(
        base_url=os.getenv("IFLOW_BASE_URL", "https://apis.iflow.cn/v1"),
        api_key=os.getenv("IFLOW_API_KEY"),
        model=os.getenv("IFLOW_MODEL", "qwen3-max"),
        temperature=float(os.getenv("IFLOW_TEMPERATURE", "0.2")),
        callbacks=[StdOutCallbackHandler()],  # 打印日志到 stdout
    )


model = build_model()

from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from langgraph.store.memory import InMemoryStore
from deepagents.backends import FilesystemBackend

file_universal_processor_agent = {
    "name": "file_universal_processor_agent",
    "description": "Used to inspect and manage the file system",
    "system_prompt": FILE_UNIVERSAL_PROCESSOR_SYSTEM_PROMPT,
    "tools": all_tools,
}

# composite_backend = lambda rt: CompositeBackend(
#     default=StateBackend(rt),
#     routes={
#         "/workspace/": FilesystemBackend(root_dir="./workspace", virtual_mode=True),
#     },
# )

composite_backend = lambda rt: CompositeBackend(
    default=FilesystemBackend(
        root_dir="./agent-states",
        virtual_mode=True,
    ),
    routes={
        "/workspace/": FilesystemBackend(
            root_dir="./workspace",
            virtual_mode=True,
        ),
    },
)
os.makedirs("./agent-states", exist_ok=True)

agent = create_deep_agent(
    model=model,
    tools=all_tools,
    system_prompt=ORCHESTRATOR_SYSTEM_PROMPT,
    subagents=[],
    backend=composite_backend,
)

# %%
# Visualize the graph (optional)
try:
    from IPython.display import Image, display

    display(Image(agent.get_graph().draw_mermaid_png()))
except Exception:
    console.print("Graph visualization unavailable in this environment.", style="red")

# %% [markdown]
# ## Example Invocation
#
# Ask the agent to render a shallow tree for the current directory. Adjust depth or entries as needed.

# %%
request_message = {
    "messages": [
        {
            "role": "user",
            "content": "Write me a /final_report.md based on the files inside the /workspace, make sure to process the files first using the file processor sub-agent and store the intermediate information into /workspace/intermediate.json file, then use that file to write the final report.md. write the summary report in pure Chinese, make it very official and academic style, targeting as a report for the central standing committee of the Communist Party of China.",
        }
    ],
}

request_message = {
    "messages": [
        {
            "role": "user",
            "content": "阅读workspace中的文件，解压压缩包，根据文件内容和我需要报销的需要，归纳整理，重命名，使得他们变得非常整齐，并且给出我一个todo-list.md，告诉我接下来我需要报销哪些文件，以及报销的理由。并且整理其中所有报销相关的信息，包括但不限于航班号，座位号，日期等等，生成一个report.md文件，告诉我这些报销信息的汇总情况。",
        }
    ],
}


# %% [markdown]
# You can read internal artifacts (e.g., `/research.md`, `/report.md`) from `example_result["files"]` if the run produced them.
for event in agent.stream(request_message):
    render_stream_event(event)
# %%
# example_result = agent.invoke(request_message)
# # %%
# format_messages(example_result["messages"])
# render_final_output(example_result)
# # %%
