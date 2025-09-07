#!/usr/bin/env python3
"""
Obsidian (Markdown) → Notion sync 
--------------------------------------------------------------

Goals
• **Correct nesting**: mirrors your Obsidian folders as real Notion *child pages*
  (no databases involved).
• **Rich Markdown → Notion**: headings, paragraphs, blockquotes, horizontal rules,
  bullet/numbered lists (with nesting), GitHub‑style checkboxes, code fences with
  language mapping & safe chunking, inline code & links, basic bold/italic/strike.
• **Images/attachments**: currently skipped entirely.

Install
    pip install -U notion-client python-dotenv

.env (minimal)
    NOTION_TOKEN=secret_...
    NOTION_PARENT_PAGE_ID=266d0960....
    MARKDOWN_BASE_DIR=/abs/path/to/vault
    CONCURRENCY_LIMIT=4   # tip: use 1 for failsafe

Run
    python obsidian2notion.py --base "/path/to/vault"

Cleanup (optional)
    # list duplicates and where they live (no changes)
    python obsidian2notion.py --dedup-sweep
    # archive extra copies (keeps the first one under each parent)
    python obsidian2notion.py --dedup-sweep --apply
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import os
import random
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

try:
    from notion_client import AsyncClient
    from notion_client.errors import APIResponseError
except Exception as e:  # pragma: no cover
    print("Install dependencies: pip install -U notion-client python-dotenv", file=sys.stderr)
    raise

# -------------------------
# Configuration
# -------------------------
@dataclasses.dataclass
class Config:
    notion_token: str
    notion_parent_page_id: str
    markdown_base_dir: Path
    concurrency_limit: int = 4

    @staticmethod
    def from_env(base_dir: Optional[str] = None,
                 concurrency: Optional[int] = None) -> "Config":
        load_dotenv()
        token = os.getenv("NOTION_TOKEN")
        parent = os.getenv("NOTION_PARENT_PAGE_ID")
        if not token or not parent:
            raise RuntimeError("NOTION_TOKEN and NOTION_PARENT_PAGE_ID are required.")
        mbd = Path(base_dir or os.getenv("MARKDOWN_BASE_DIR", ".")).expanduser().resolve()
        return Config(
            notion_token=token,
            notion_parent_page_id=parent,
            markdown_base_dir=mbd,
            concurrency_limit=int(concurrency or os.getenv("CONCURRENCY_LIMIT", "4")),
        )

# -------------------------
# Markdown parsing helpers
# -------------------------
MD_EXTENSIONS = {".md", ".markdown"}

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
HR_RE = re.compile(r"^\s*---\s*$")
CODE_FENCE_RE = re.compile(r"^\s*(```|~~~)(\w+)?\s*$")
BLOCKQUOTE_RE = re.compile(r"^\s*>\s?(.*)$")
ULIST_RE = re.compile(r"^(?P<indent>\s*)([*+-])\s+(?P<text>.*)$")
OLIST_RE = re.compile(r"^(?P<indent>\s*)(\d+)[\.)]\s+(?P<text>.*)$")
TASK_RE = re.compile(r"^(?P<indent>\s*)[*+-]\s+\[(?P<mark>[ xX])\]\s+(?P<text>.*)$")
IMAGE_LINE_RE = re.compile(r"^\s*!\[.*?\]\(.*?\)\s*$|^\s*!\[\[.*?\]\]\s*$")  # we skip
LINK_RE = re.compile(r"\[(.*?)\]\((https?://[^\s)]+)\)")
CODE_SPAN_RE = re.compile(r"`([^`]+)`")
EMPH_TOKEN_RE = re.compile(r"(\*\*[^*]+\*\*|\*[^*]+\*|~~[^~]+~~)")

# Notion code languages
ALLOWED_LANGS = {
    "abap","abc","agda","arduino","ascii art","assembly","bash","basic","bnf","c","c#","c++","clojure",
    "coffeescript","coq","css","dart","dhall","diff","docker","ebnf","elixir","elm","erlang","f#","flow",
    "fortran","gherkin","glsl","go","graphql","groovy","haskell","hcl","html","idris","java","javascript",
    "json","julia","kotlin","latex","less","lisp","livescript","llvm ir","lua","makefile","markdown","markup",
    "matlab","mathematica","mermaid","nix","notion formula","objective-c","ocaml","pascal","perl","php","plain text",
    "powershell","prolog","protobuf","purescript","python","r","racket","reason","ruby","rust","sass","scala",
    "scheme","scss","shell","smalltalk","solidity","sql","swift","toml","typescript","vb.net","verilog","vhdl",
    "visual basic","webassembly","xml","yaml","java/c/c++/c#"
}
LANG_ALIASES = {
    "js": "javascript", "node": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "typescript", "yml": "yaml", "sh": "bash", "zsh": "bash", "ksh": "bash",
    "ps": "powershell", "ps1": "powershell", "cpp": "c++", "cc": "c++",
    "objc": "objective-c", "tf": "hcl", "terraform": "hcl", "md": "markdown",
    "dockerfile": "docker", "k8s": "yaml", "plaintext": "plain text", "txt": "plain text",
}


def canonical_lang(lang: Optional[str]) -> str:
    if not lang:
        return "plain text"
    l = LANG_ALIASES.get(lang.strip().lower(), lang.strip().lower())
    return l if l in ALLOWED_LANGS else "plain text"


def find_markdown_files(base: Path) -> List[Path]:
    files: List[Path] = []
    for root, _dirs, filenames in os.walk(base):
        for name in filenames:
            p = Path(root) / name
            if p.suffix.lower() in MD_EXTENSIONS:
                files.append(p)
    return files


def stat_creation_date(path: Path) -> str:
    st = path.stat()
    ts = getattr(st, "st_birthtime", st.st_mtime)
    return dt.date.fromtimestamp(ts).isoformat()


def chunk_text(s: str, size: int = 1800) -> List[str]:
    return [s[i:i+size] for i in range(0, len(s), size)] if s else []

# -------------------------
# Notion helpers (race‑free nested pages)
# -------------------------
class Notion:
    def __init__(self, cfg: Config):
        self.client = AsyncClient(auth=cfg.notion_token)
        self.parent_page_id = cfg.notion_parent_page_id
        # ParentID → {title → page_id}
        self._children_cache: Dict[str, Dict[str, str]] = {}
        # (ParentID, title) → asyncio.Lock
        self._name_locks: Dict[Tuple[str, str], asyncio.Lock] = {}

    async def _retry(self, coro_fn, *args, **kwargs):
        backoff = 1.0
        for _ in range(7):
            try:
                return await coro_fn(*args, **kwargs)
            except APIResponseError as e:  # type: ignore
                status = getattr(e, "status", None)
                msg = str(e).lower()
                if status in (409, 429) or "rate_limited" in msg or "conflict" in msg:
                    await asyncio.sleep(backoff + random.random() * 0.5)
                    backoff = min(backoff * 2, 10)
                    continue
                raise

    def _get_name_lock(self, parent_id: str, title: str) -> asyncio.Lock:
        key = (parent_id, title)
        lock = self._name_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._name_locks[key] = lock
        return lock

    async def list_child_pages(self, parent_page_id: str) -> Dict[str, str]:
        cache = dict(self._children_cache.get(parent_page_id, {}))
        start_cursor: Optional[str] = None
        while True:
            resp = await self._retry(self.client.blocks.children.list, block_id=parent_page_id, start_cursor=start_cursor)
            for b in resp.get("results", []):
                if b.get("type") == "child_page":
                    t = b.get("child_page", {}).get("title")
                    if t:
                        cache[t] = b["id"]
            if resp.get("has_more"):
                start_cursor = resp.get("next_cursor")
            else:
                break
        self._children_cache[parent_page_id] = cache
        return dict(cache)

    async def ensure_path_pages(self, root_page_id: str, path: Path) -> str:
        parent = root_page_id
        segments = [p for p in path.parts if p not in (".", "")]
        for seg in segments:
            lock = self._get_name_lock(parent, seg)
            async with lock:
                children = await self.list_child_pages(parent)
                if seg in children:
                    parent = children[seg]
                    continue
                page = await self._retry(
                    self.client.pages.create,
                    parent={"type": "page_id", "page_id": parent},
                    properties={"title": {"title": [{"type": "text", "text": {"content": seg}}]}},
                )
                # Update cache immediately so other workers see it
                self._children_cache.setdefault(parent, {})[seg] = page["id"]
                parent = page["id"]
        return parent

    # Rich‑text helpers
    @staticmethod
    def _rt_nodes(text: str, href: Optional[str] = None, **ann) -> List[Dict]:
        nodes: List[Dict] = []
        for seg in chunk_text(text, 1800):
            node = {"type": "text", "text": {"content": seg}}
            if href:
                node["text"]["link"] = {"url": href}
            if ann:
                node["annotations"] = {
                    "bold": ann.get("bold", False),
                    "italic": ann.get("italic", False),
                    "strikethrough": ann.get("strikethrough", False),
                    "underline": ann.get("underline", False),
                    "code": ann.get("code", False),
                    "color": "default",
                }
            nodes.append(node)
        return nodes

    def _emit_emphasis(self, text: str) -> List[Dict]:
        parts: List[Dict] = []
        pos = 0
        for m in EMPH_TOKEN_RE.finditer(text):
            pre = text[pos:m.start()]
            if pre:
                parts.extend(self._rt_nodes(pre))
            tok = m.group(0)
            if tok.startswith("**"):
                parts.extend(self._rt_nodes(tok[2:-2], bold=True))
            elif tok.startswith("~~"):
                parts.extend(self._rt_nodes(tok[2:-2], strikethrough=True))
            else:  # *italic*
                parts.extend(self._rt_nodes(tok[1:-1], italic=True))
            pos = m.end()
        tail = text[pos:]
        if tail:
            parts.extend(self._rt_nodes(tail))
        return parts

    def _linkify(self, segment: str) -> List[Dict]:
        out: List[Dict] = []
        pos = 0
        for m in LINK_RE.finditer(segment):
            pre = segment[pos:m.start()]
            if pre:
                out.extend(self._emit_emphasis(pre))
            txt, url = m.group(1), m.group(2)
            # Link text may contain emphasis; keep href on each chunk
            for node in self._emit_emphasis(txt):
                if node.get("type") == "text":
                    node["text"]["link"] = {"url": url}
                out.append(node)
            pos = m.end()
        tail = segment[pos:]
        if tail:
            out.extend(self._emit_emphasis(tail))
        return out

    def _inline_rt(self, text: str) -> List[Dict]:
        parts: List[Dict] = []
        pos = 0
        for m in CODE_SPAN_RE.finditer(text):
            pre = text[pos:m.start()]
            if pre:
                parts.extend(self._linkify(pre))
            code_text = m.group(1)
            parts.extend(self._rt_nodes(code_text, code=True))
            pos = m.end()
        tail = text[pos:]
        if tail:
            parts.extend(self._linkify(tail))
        return parts

    # -------------------------
    # Markdown → Notion blocks
    # -------------------------
    def md_to_blocks(self, md: str) -> List[Dict]:
        blocks: List[Dict] = []
        paragraph_buf: List[str] = []
        in_code = False
        code_lang = "plain text"
        code_lines: List[str] = []

        def flush_paragraph():
            nonlocal paragraph_buf
            if paragraph_buf:
                text = " ".join(line.strip() for line in paragraph_buf).strip()
                if text:
                    blocks.append({
                        "type": "paragraph",
                        "paragraph": {"rich_text": self._inline_rt(text)}
                    })
            paragraph_buf = []

        def flush_code():
            nonlocal code_lines
            if code_lines:
                code_text = "\n".join(code_lines)
                rich = []
                for seg in chunk_text(code_text, 1800):
                    rich.extend(self._rt_nodes(seg))
                blocks.append({
                    "type": "code",
                    "code": {
                        "rich_text": rich,
                        "language": canonical_lang(code_lang),
                    },
                })
            code_lines = []

        lines = md.replace("\t", "    ").splitlines()
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]

            if IMAGE_LINE_RE.match(line):  # skip images entirely
                flush_paragraph()
                i += 1
                continue

            m_code = CODE_FENCE_RE.match(line)
            if m_code:
                if in_code:
                    flush_code()
                    in_code = False
                else:
                    in_code = True
                    code_lang = (m_code.group(2) or "plain text").lower()
                i += 1
                continue
            if in_code:
                code_lines.append(line)
                i += 1
                continue

            if HR_RE.match(line):
                flush_paragraph()
                blocks.append({"type": "divider", "divider": {}})
                i += 1
                continue

            m_bq = BLOCKQUOTE_RE.match(line)
            if m_bq:
                flush_paragraph()
                quote_lines = [m_bq.group(1)]
                i += 1
                while i < n:
                    m2 = BLOCKQUOTE_RE.match(lines[i])
                    if not m2:
                        break
                    quote_lines.append(m2.group(1))
                    i += 1
                quote_text = " ".join(s.strip() for s in quote_lines).strip()
                blocks.append({
                    "type": "quote",
                    "quote": {"rich_text": self._inline_rt(quote_text)}
                })
                continue

            # Lists (including nested & checkboxes)
            if TASK_RE.match(line) or ULIST_RE.match(line) or OLIST_RE.match(line):
                flush_paragraph()
                list_blocks, new_i = self._parse_list(lines, i)
                blocks.extend(list_blocks)
                i = new_i
                continue

            m_h = HEADING_RE.match(line)
            if m_h:
                flush_paragraph()
                level = min(len(m_h.group(1)), 3)
                text = m_h.group(2).strip()
                blocks.append({
                    f"type": f"heading_{level}",
                    f"heading_{level}": {"rich_text": self._inline_rt(text)},
                })
                i += 1
                continue

            if not line.strip():
                flush_paragraph()
                i += 1
                continue

            paragraph_buf.append(line)
            i += 1

        if in_code:
            flush_code()
        flush_paragraph()
        return blocks

    def _parse_list(self, lines: List[str], i: int) -> Tuple[List[Dict], int]:
        """Parse consecutive list lines (ul/ol/task) with indentation nesting.
        Indent unit = 2 spaces. Children belong at the *block* level (not inside the list payload).
        """
        root: List[Dict] = []
        containers: List[Tuple[int, List[Dict]]] = [(0, root)]  # (level, children_list)
        last_item_for_level: Dict[int, Dict] = {}
    
        def current_container() -> List[Dict]:
            return containers[-1][1]
    
        n = len(lines)
        while i < n:
            line = lines[i]
            mt = TASK_RE.match(line)
            mu = ULIST_RE.match(line)
            mo = OLIST_RE.match(line)
            if not (mt or mu or mo):
                break
    
            if mt:
                indent = len(mt.group("indent"))
                level = indent // 2
                checked = mt.group("mark").lower() == "x"
                text = mt.group("text").strip()
                block = {
                    "type": "to_do",
                    "to_do": {"rich_text": self._inline_rt(text), "checked": checked}
                }
            else:
                indent = len((mu or mo).group("indent"))
                level = indent // 2
                text = (mu or mo).group("text").strip()
                key = "bulleted_list_item" if mu else "numbered_list_item"
                block = {"type": key, key: {"rich_text": self._inline_rt(text)}}
    
            # normalize stack to target level
            while containers and containers[-1][0] > level:
                containers.pop()
            while containers[-1][0] < level:
                prev_level = containers[-1][0]
                parent_item = last_item_for_level.get(prev_level)
                if not parent_item:
                    level = prev_level
                    break
                # ✅ block-level children (correct for Notion)
                children = parent_item.setdefault("children", [])
                containers.append((prev_level + 1, children))
    
            current_container().append(block)
            last_item_for_level[level] = block
            i += 1
    
        return root, i

# -------------------------
# Syncer (nesting only)
# -------------------------
class Syncer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.notion = Notion(cfg)
        self.sem = asyncio.Semaphore(cfg.concurrency_limit)

    async def _append_blocks_in_chunks(self, parent_id: str, blocks: List[Dict]):
        for i in range(0, len(blocks), 100):
            await self.notion._retry(
                self.notion.client.blocks.children.append,
                block_id=parent_id,
                children=blocks[i:i+100],
            )

    async def process_file(self, file_path: Path):
        page_title = file_path.stem
        relative_path = file_path.parent.relative_to(self.cfg.markdown_base_dir)

        async with self.sem:
            try:
                md = file_path.read_text(encoding="utf-8")
                blocks = self.notion.md_to_blocks(md)

                # Ensure folder path exists (race‑free)
                parent = await self.notion.ensure_path_pages(self.cfg.notion_parent_page_id, relative_path)

                # Final page creation, guarded by lock
                lock = self.notion._get_name_lock(parent, page_title)
                async with lock:
                    children = await self.notion.list_child_pages(parent)
                    if page_title in children:
                        print(f"⏭️  Skipping (already exists): {page_title}")
                        return
                    page = await self.notion._retry(
                        self.notion.client.pages.create,
                        parent={"type": "page_id", "page_id": parent},
                        properties={"title": {"title": [{"type": "text", "text": {"content": page_title}}]}},
                    )
                    # cache immediately so siblings see it
                    self.notion._children_cache.setdefault(parent, {})[page_title] = page["id"]

                await self._append_blocks_in_chunks(page["id"], blocks)
                print(f"✅ Synced: {page_title}")
            except Exception as e:
                print(f"❌ ERROR syncing '{page_title}': {e}")

    async def process_all(self):
        all_files = find_markdown_files(self.cfg.markdown_base_dir)
        if not all_files:
            print("No Markdown files found.")
            return
        print(f"\nFound {len(all_files)} local files. Starting sync with concurrency {self.cfg.concurrency_limit}...\n")
        tasks = [asyncio.create_task(self.process_file(p)) for p in all_files]
        for i in range(0, len(tasks), self.cfg.concurrency_limit * 4):
            batch = tasks[i:i + self.cfg.concurrency_limit * 4]
            await asyncio.gather(*batch)
        print("\nAll files processed! 🚀")

    # -------- Duplicate sweep (optional) --------
    async def dedup_sweep(self, root_page_id: str, apply: bool = False):
        """Find duplicate child_page titles under each parent. If apply=True,
        archive extras (keep first)."""
        async def walk(parent: str):
            seen: Dict[str, List[str]] = {}
            start_cursor: Optional[str] = None
            while True:
                resp = await self.notion._retry(self.notion.client.blocks.children.list, block_id=parent, start_cursor=start_cursor)
                for b in resp.get("results", []):
                    if b.get("type") == "child_page":
                        t = b.get("child_page", {}).get("title")
                        if not t:
                            continue
                        seen.setdefault(t, []).append(b["id"])
                        await walk(b["id"])  # depth‑first
                if resp.get("has_more"):
                    start_cursor = resp.get("next_cursor")
                else:
                    break
            for title, ids in seen.items():
                if len(ids) > 1:
                    print(f"[DUP] '{title}' under {parent}: {ids}")
                    if apply:
                        for pid in ids[1:]:
                            await self.notion._retry(self.notion.client.pages.update, page_id=pid, archived=True)
                            print(f"  → archived {pid}")
        await walk(root_page_id)

# -------------------------
# CLI
# -------------------------

def main(argv: Optional[List[str]] = None):
    import argparse

    parser = argparse.ArgumentParser(description="Sync an Obsidian vault to Notion (nested pages, race‑free)")
    parser.add_argument("--base", dest="base", help="Path to Obsidian vault (MARKDOWN_BASE_DIR)")
    parser.add_argument("--concurrency", dest="concurrency", type=int, default=None, help="Parallel file workers")
    parser.add_argument("--dedup-sweep", dest="dedup", action="store_true", help="List duplicate child pages; add --apply to archive extras")
    parser.add_argument("--apply", dest="apply", action="store_true", help="With --dedup-sweep: archive duplicates (keep first)")
    args = parser.parse_args(argv)

    cfg = Config.from_env(base_dir=args.base, concurrency=args.concurrency)
    syncer = Syncer(cfg)

    if args.dedup:
        asyncio.run(syncer.dedup_sweep(cfg.notion_parent_page_id, apply=args.apply))
    else:
        asyncio.run(syncer.process_all())


if __name__ == "__main__":
    main()
