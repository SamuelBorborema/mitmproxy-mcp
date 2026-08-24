"""Pure helpers for diff_flows mesh comparison.

All functions are stdlib-only (difflib, json, hashlib) and have no
side-effects. They are designed to be testable without a DB or live flows.

Key design decisions:
- diff_headers is case-insensitive and uses Counter (multiset) so duplicate
  Set-Cookie values are correctly compared.
- diff_bodies handles text / json / hex / none modes and guards large bodies
  via sha256 + truncated preview.
- Binary detection uses surrogate-escape and null-byte heuristics.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()


def _is_mostly_binary(text: str) -> bool:
    """Heuristic binary detection.

    Uses null-byte, surrogate-codepoint and control-char ratio checks.
    ``get_safe_text`` returns None for binary messages, but when we fall
    back to live-flow bytes decoded with surrogateescape the surrogate
    codepoints remain. We treat those as binary.
    """
    if not text:
        return False
    if "\x00" in text:
        return True
    # surrogate codepoints from surrogateescape
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            return True
    # count replacement char and control chars (excluding whitespace)
    non_printable = 0
    for ch in text:
        cp = ord(ch)
        if cp == 0xFFFD:
            non_printable += 1
        elif cp < 0x20 and ch not in ("\n", "\r", "\t"):
            non_printable += 1
        elif cp == 0x7F:
            non_printable += 1
    if len(text) > 0 and non_printable / len(text) > 0.30:
        return True
    return False


def _hex_lines(data: bytes, width: int = 16) -> List[str]:
    """Render bytes as spaced hex dump lines."""
    lines: List[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        lines.append(" ".join(f"{b:02x}" for b in chunk))
    return lines


def _to_bytes(text: str) -> bytes:
    """Encode text back to bytes using surrogateescape to preserve binary."""
    return text.encode("utf-8", errors="surrogateescape")


def diff_headers(
    ordered_a: Any,
    ordered_b: Any,
) -> Dict[str, Any]:
    """Compare two header collections case-insensitively with multiset semantics.

    Args:
        ordered_a / ordered_b: either dict {k:v} or list of [k, v] pairs
            (as stored by TrafficDB). Duplicate keys (e.g. Set-Cookie) are
            preserved via Counter.

    Returns:
        {added, removed, modified, unchanged}
        - added: headers present only in b
        - removed: present only in a
        - modified: same key but different multiset of values
        - unchanged: list of keys with identical multisets
    """

    def normalize(ordered) -> Dict[str, Counter]:
        if ordered is None:
            return {}
        if isinstance(ordered, dict):
            # dict values are single strings
            return {str(k).lower(): Counter([str(v)]) for k, v in ordered.items()}
        # list of pairs
        result: Dict[str, Counter] = {}
        for item in ordered:
            # handle both [k,v] and (k,v)
            if not item or len(item) < 2:
                continue
            k, v = item[0], item[1]
            lk = str(k).lower()
            if lk not in result:
                result[lk] = Counter()
            result[lk][str(v)] += 1
        return result

    norm_a = normalize(ordered_a)
    norm_b = normalize(ordered_b)

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    modified: List[Dict[str, Any]] = []
    unchanged: List[str] = []

    all_keys = set(norm_a.keys()) | set(norm_b.keys())
    for key in sorted(all_keys):
        ca = norm_a.get(key)
        cb = norm_b.get(key)
        if ca is None:
            # only in B
            vals = list(cb.elements())  # type: ignore[union-attr]
            added.append({"key": key, "values": vals, "count": len(vals)})
        elif cb is None:
            vals = list(ca.elements())
            removed.append({"key": key, "values": vals, "count": len(vals)})
        elif ca != cb:
            modified.append(
                {
                    "key": key,
                    "a_values": list(ca.elements()),
                    "b_values": list(cb.elements()),
                    "a_counter": dict(ca),
                    "b_counter": dict(cb),
                }
            )
        else:
            unchanged.append(key)

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
    }


def _json_structural_diff(a_obj: Any, b_obj: Any) -> Dict[str, Any]:
    """Compute added/removed/type_changed/value_changed for JSON objects."""
    result: Dict[str, Any] = {}
    if isinstance(a_obj, dict) and isinstance(b_obj, dict):
        a_keys = set(a_obj.keys())
        b_keys = set(b_obj.keys())
        added = sorted(list(b_keys - a_keys))
        removed = sorted(list(a_keys - b_keys))
        type_changed: List[str] = []
        value_changed: List[str] = []
        common = a_keys & b_keys
        for k in sorted(common):
            av = a_obj[k]
            bv = b_obj[k]
            if type(av).__name__ != type(bv).__name__:
                # special: bool vs int handling – bool is subclass of int
                # we already handled via type name, but bool/int considered different per spec
                type_changed.append(k)
            elif av != bv:
                value_changed.append(k)
        result = {
            "added": added,
            "removed": removed,
            "type_changed": type_changed,
            "value_changed": value_changed,
        }
        # nested diff count
        result["diff_count"] = len(added) + len(removed) + len(type_changed) + len(value_changed)
    elif isinstance(a_obj, list) and isinstance(b_obj, list):
        result = {
            "len_a": len(a_obj),
            "len_b": len(b_obj),
            "len_delta": len(b_obj) - len(a_obj),
            "added_indices": [],
            "removed_indices": [],
        }
        # simple list diff: compare up to min len
        min_len = min(len(a_obj), len(b_obj))
        diff_indices = [i for i in range(min_len) if a_obj[i] != b_obj[i]]
        result["diff_indices"] = diff_indices
        result["diff_count"] = len(diff_indices) + abs(len(a_obj) - len(b_obj))
    else:
        # primitive or type mismatch
        result = {
            "type_a": type(a_obj).__name__,
            "type_b": type(b_obj).__name__,
            "value_a": a_obj,
            "value_b": b_obj,
            "diff": a_obj != b_obj,
        }
    return result


def _unified_diff(a_str: str, b_str: str, context_lines: int = 5) -> str:
    a_lines = a_str.splitlines(keepends=False)
    b_lines = b_str.splitlines(keepends=False)
    diff = difflib.unified_diff(
        a_lines,
        b_lines,
        fromfile="a",
        tofile="b",
        lineterm="",
        n=context_lines,
    )
    return "\n".join(diff)


def diff_bodies(
    a_str: Optional[str],
    b_str: Optional[str],
    mode: str = "auto",
    max_body_chars: int = 20000,
    context_lines: int = 5,
    content_type_a: Optional[str] = None,
    content_type_b: Optional[str] = None,
    size_a: Optional[int] = None,
    size_b: Optional[int] = None,
) -> Dict[str, Any]:
    """Diff two bodies with mode branching and large-body guard.

    Args:
        a_str/b_str: body strings or None (None indicates missing/binary)
        mode: auto|text|json|hex|none
        max_body_chars: guard – bodies larger than this are truncated and sha256-hashed
        context_lines: unified diff context
        content_type_a/b: for note when both bodies None
        size_a/b: for note when both bodies None

    Returns:
        dict with diff_type, unified, json_diff, truncated, sha256, previews, warnings
    """
    warnings: List[str] = []

    # mode validation handled by caller; but we normalize
    mode = mode.lower() if mode else "auto"

    if mode == "none":
        return {
            "diff_type": "none",
            "unified": None,
            "json_diff": None,
            "truncated": False,
            "warnings": warnings,
            "note": "body diff skipped (mode=none)",
        }

    # Both None – typically binary or empty
    if a_str is None and b_str is None:
        # compare via size / content-type if available
        note = "both bodies are None/empty – comparing size/content-type only"
        if content_type_a or content_type_b:
            note += f"; content_type a={content_type_a} b={content_type_b}"
        return {
            "diff_type": "none",
            "unified": None,
            "json_diff": None,
            "truncated": False,
            "warnings": warnings,
            "note": note,
            "size_a": size_a,
            "size_b": size_b,
        }

    # One None, other not – produce diff
    if a_str is None or b_str is None:
        # For binary fallback, treat None as empty for hex diff if mode hex
        # Otherwise report diff
        a_repr = a_str if a_str is not None else ""
        b_repr = b_str if b_str is not None else ""
        # Detect binary in the non-None side
        non_none = b_str if a_str is None else a_str
        is_bin = _is_mostly_binary(non_none) if non_none else False
        if is_bin and mode == "auto":
            # switch to hex handling
            mode = "hex"
        if mode == "hex":
            # hex diff for binary vs empty
            a_bytes = _to_bytes(a_repr) if a_str is not None else b""
            b_bytes = _to_bytes(b_repr) if b_str is not None else b""
            a_lines = _hex_lines(a_bytes)
            b_lines = _hex_lines(b_bytes)
            unified = "\n".join(
                difflib.unified_diff(a_lines, b_lines, fromfile="a (hex)", tofile="b (hex)", lineterm="", n=context_lines)
            )
            # large guard for hex already considered via string length
            truncated = False
            sha_a = _sha256(a_repr) if a_str is not None else None
            sha_b = _sha256(b_repr) if b_str is not None else None
            if a_str is not None and len(a_str) > max_body_chars:
                truncated = True
                warnings.append(f"body a truncated: {len(a_str)} > max_body_chars {max_body_chars} (sha256 {sha_a})")
            if b_str is not None and len(b_str) > max_body_chars:
                truncated = True
                warnings.append(f"body b truncated: {len(b_str)} > max_body_chars {max_body_chars} (sha256 {sha_b})")
            return {
                "diff_type": "hex",
                "unified": unified,
                "json_diff": None,
                "truncated": truncated,
                "sha256_a": sha_a,
                "sha256_b": sha_b,
                "warnings": warnings,
                "binary": True,
            }
        # default text diff for one None
        truncated = False
        sha_a = _sha256(a_repr) if a_str is not None else None
        sha_b = _sha256(b_repr) if b_str is not None else None
        if a_str is not None and len(a_str) > max_body_chars:
            truncated = True
            warnings.append(f"body a truncated preview: {len(a_str)} > {max_body_chars}")
            a_repr = a_repr[:max_body_chars]
        if b_str is not None and len(b_str) > max_body_chars:
            truncated = True
            warnings.append(f"body b truncated preview: {len(b_str)} > {max_body_chars}")
            b_repr = b_repr[:max_body_chars]
        unified = _unified_diff(a_repr, b_repr, context_lines)
        return {
            "diff_type": "text",
            "unified": unified,
            "json_diff": None,
            "truncated": truncated,
            "sha256_a": sha_a,
            "sha256_b": sha_b,
            "warnings": warnings,
        }

    # Both are strings now
    assert isinstance(a_str, str) and isinstance(b_str, str)

    # Large body guard via sha256 + preview
    truncated = False
    sha_a = _sha256(a_str)
    sha_b = _sha256(b_str)
    preview_a = a_str
    preview_b = b_str
    if len(a_str) > max_body_chars or len(b_str) > max_body_chars:
        truncated = True
        # keep preview for diff but warn
        if len(a_str) > max_body_chars:
            warnings.append(f"body a exceeds max_body_chars ({len(a_str)} > {max_body_chars}); sha256 {sha_a}")
            preview_a = a_str[:max_body_chars]
        if len(b_str) > max_body_chars:
            warnings.append(f"body b exceeds max_body_chars ({len(b_str)} > {max_body_chars}); sha256 {sha_b}")
            preview_b = b_str[:max_body_chars]
        # unified diff on preview
        # also note that full diff is truncated

    # Binary detection for hex branching
    a_is_bin = _is_mostly_binary(a_str)
    b_is_bin = _is_mostly_binary(b_str)
    is_binary = a_is_bin or b_is_bin

    # Determine effective mode
    effective_mode = mode
    if mode == "auto":
        if is_binary:
            effective_mode = "hex"
        else:
            # try json
            try:
                a_json = json.loads(a_str)
                b_json = json.loads(b_str)
                # if both parse, use json mode
                effective_mode = "json"
            except Exception:
                effective_mode = "text"

    if effective_mode == "hex":
        # hex diff
        a_bytes = _to_bytes(a_str)
        b_bytes = _to_bytes(b_str)
        # if truncated, use preview bytes
        if truncated:
            a_bytes = _to_bytes(preview_a)
            b_bytes = _to_bytes(preview_b)
            # still include sha of full
        a_lines = _hex_lines(a_bytes)
        b_lines = _hex_lines(b_bytes)
        unified = "\n".join(
            difflib.unified_diff(a_lines, b_lines, fromfile="a (hex)", tofile="b (hex)", lineterm="", n=context_lines)
        )
        return {
            "diff_type": "hex",
            "unified": unified,
            "json_diff": None,
            "truncated": truncated,
            "sha256_a": sha_a,
            "sha256_b": sha_b,
            "warnings": warnings,
            "binary": is_binary,
        }

    if effective_mode == "json":
        try:
            a_json = json.loads(a_str)
            b_json = json.loads(b_str)
        except Exception as e:
            # fallback to text if json parse fails despite earlier success (e.g. truncated)
            warnings.append(f"json parse failed, falling back to text: {e}")
            unified = _unified_diff(preview_a, preview_b, context_lines)
            return {
                "diff_type": "text",
                "unified": unified,
                "json_diff": None,
                "truncated": truncated,
                "sha256_a": sha_a,
                "sha256_b": sha_b,
                "warnings": warnings,
            }
        json_diff = _json_structural_diff(a_json, b_json)
        # unified diff on pretty-printed JSON
        try:
            a_pretty = json.dumps(a_json, indent=2, sort_keys=True, ensure_ascii=False)
            b_pretty = json.dumps(b_json, indent=2, sort_keys=True, ensure_ascii=False)
            # if truncated, we diff pretty of preview? but json may be broken; use text fallback
            if truncated:
                # we have sha for full, but preview may not be valid json
                # try to pretty print truncated preview's json if possible, else diff raw preview
                try:
                    a_prev_json = json.loads(preview_a)
                    b_prev_json = json.loads(preview_b)
                    a_pretty = json.dumps(a_prev_json, indent=2, sort_keys=True, ensure_ascii=False)
                    b_pretty = json.dumps(b_prev_json, indent=2, sort_keys=True, ensure_ascii=False)
                except Exception:
                    a_pretty = preview_a
                    b_pretty = preview_b
            unified = _unified_diff(a_pretty, b_pretty, context_lines)
        except Exception:
            unified = _unified_diff(preview_a, preview_b, context_lines)

        return {
            "diff_type": "json",
            "unified": unified,
            "json_diff": json_diff,
            "truncated": truncated,
            "sha256_a": sha_a,
            "sha256_b": sha_b,
            "warnings": warnings,
        }

    # text mode (or fallback)
    # if binary but mode text, still diff as text but warn
    if is_binary:
        warnings.append("binary content diffed as text (consider hex mode)")
    unified = _unified_diff(preview_a, preview_b, context_lines)
    return {
        "diff_type": "text",
        "unified": unified,
        "json_diff": None,
        "truncated": truncated,
        "sha256_a": sha_a,
        "sha256_b": sha_b,
        "warnings": warnings,
        "binary": is_binary,
    }


def diff_status(a_status: Optional[int], b_status: Optional[int]) -> Dict[str, Any]:
    return {
        "a": a_status,
        "b": b_status,
        "diff": a_status != b_status,
        "same": a_status == b_status,
    }


def diff_size(a_size: Optional[int], b_size: Optional[int]) -> Dict[str, Any]:
    if a_size is None:
        a_size = 0
    if b_size is None:
        b_size = 0
    delta = b_size - a_size
    ratio: Optional[float] = None
    if a_size and a_size != 0:
        try:
            ratio = b_size / a_size
        except Exception:
            ratio = None
    elif b_size == 0 and a_size == 0:
        ratio = 1.0
    else:
        ratio = None
    return {
        "a": a_size,
        "b": b_size,
        "delta": delta,
        "ratio": ratio,
        "diff": a_size != b_size,
    }


def diff_timestamp(a_ts: Optional[float], b_ts: Optional[float]) -> Optional[float]:
    if a_ts is None or b_ts is None:
        return None
    try:
        return float(b_ts) - float(a_ts)
    except Exception:
        return None

