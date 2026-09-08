#!/usr/bin/env python3
"""Build a deterministic, source-only Android file relation graph.

The graph is deliberately lighter than a compiler graph.  It connects files
using evidence that is useful even when Gradle and language servers cannot be
executed: exact imports, unique type references, Android component names,
resource references, source-set overlays, and Gradle project dependencies.

Every edge keeps its reason and source evidence.  Consumers must treat the
graph as navigation context, not as proof of runtime reachability.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


_MAX_FILE_BYTES = 800_000
_CODE_EXTENSIONS = {".java", ".kt", ".kts", ".aidl"}
_XML_EXTENSION = ".xml"
_PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)")
_IMPORT_RE = re.compile(
    r"(?m)^\s*import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\.\*)?)"
    r"(?:\s+as\s+[A-Za-z_]\w*)?"
)
_TYPE_DECL_RE = re.compile(
    r"\b(?:(?:data|sealed|enum|annotation|value|open|abstract)\s+)*"
    r"(class|interface|object|enum|record)\s+([A-Za-z_]\w*)"
)
_IDENTIFIER_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]{1,}\b")
_RESOURCE_RE = re.compile(r"\bR\.([A-Za-z_]\w*)\.([A-Za-z_]\w*)|@\+?([A-Za-z_]\w*)/([A-Za-z_]\w*)")
_XML_CLASS_ATTR_RE = re.compile(
    r"(?:android:)?(?:name|targetActivity|parentActivityName|backupAgent|manageSpaceActivity|class)"
    r"\s*=\s*['\"]([.$A-Za-z_][\w.$]*)['\"]"
)
_XML_TAG_CLASS_RE = re.compile(r"<\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)(?:\s|/|>)")
_MANIFEST_PACKAGE_RE = re.compile(r"<manifest\b[^>]*\bpackage\s*=\s*['\"]([\w.]+)['\"]")
_PROJECT_DEP_RE = re.compile(
    r"project\s*\(\s*(?:path\s*(?:=|:)\s*)?['\"]:([^'\"]+)['\"]\s*\)"
)
_XML_OPEN_TAG_RE = re.compile(r"<\s*([A-Za-z_][\w.-]*)\b([^>]*)>")
_XML_NAME_ATTR_RE = re.compile(r"\bname\s*=\s*['\"]([A-Za-z_]\w*)['\"]")
_XML_TYPE_ATTR_RE = re.compile(r"\btype\s*=\s*['\"]([A-Za-z_]\w*)['\"]")
_INLINE_ID_DEF_RE = re.compile(r"@\+id/([A-Za-z_]\w*)")
_SOURCE_SET_RE = re.compile(r"^(?:(?P<module>.+?)/)?src/(?P<source_set>[^/]+)/(?P<tail>.+)$")
_RESOURCE_PATH_RE = re.compile(
    r"^(?:(?P<module>.+?)/)?src/(?P<source_set>[^/]+)/res/"
    r"(?P<resource_type>[^/]+)/(?P<name>[^/.]+)\.[^/]+$"
)

_EDGE_WEIGHTS = {
    "android_component": 8,
    "android_resource": 6,
    "source_set_overlay": 6,
    "gradle_project": 5,
    "exact_import": 5,
    "unique_type_reference": 3,
}


def _read_text(path: Path) -> tuple[str, str]:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return "", "oversized"
        return path.read_text(encoding="utf-8", errors="replace"), "complete"
    except OSError:
        return "", "unreadable"


def _module_and_source_set(rel: str) -> tuple[str, str, str]:
    match = _SOURCE_SET_RE.match(rel)
    if not match:
        return "", "", ""
    return (
        match.group("module") or "",
        match.group("source_set"),
        match.group("tail"),
    )


def _resource_key(rel: str) -> tuple[str, str, str, str] | None:
    match = _RESOURCE_PATH_RE.match(rel)
    if not match:
        return None
    resource_type = match.group("resource_type").split("-", 1)[0]
    return (
        match.group("module") or "",
        match.group("source_set"),
        resource_type,
        match.group("name"),
    )


def _expand_android_class(value: str, package: str) -> str:
    value = value.strip()
    if value.startswith("."):
        return package + value if package else value[1:]
    if "." not in value and package:
        return f"{package}.{value}"
    return value


def _xml_resource_definitions(rel: str, text: str) -> set[tuple[str, str]]:
    """Extract values resources and inline ``@+id`` declarations."""
    definitions = {("id", name) for name in _INLINE_ID_DEF_RE.findall(text)}
    resource = _resource_key(rel)
    if not resource or resource[2] != "values":
        return definitions
    tag_types = {
        "string": "string", "color": "color", "dimen": "dimen",
        "bool": "bool", "integer": "integer", "plurals": "plurals",
        "style": "style", "attr": "attr", "declare-styleable": "styleable",
        "string-array": "array", "integer-array": "array", "array": "array",
    }
    for tag, attrs in _XML_OPEN_TAG_RE.findall(text):
        name_match = _XML_NAME_ATTR_RE.search(attrs)
        if not name_match:
            continue
        resource_type = tag_types.get(tag)
        if tag == "item":
            type_match = _XML_TYPE_ATTR_RE.search(attrs)
            resource_type = type_match.group(1) if type_match else None
        if resource_type:
            definitions.add((resource_type, name_match.group(1)))
    return definitions


def _inspect_file(repo_root: Path, rel: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = repo_root / rel
    text, analysis_state = _read_text(path)
    module, source_set, overlay_tail = _module_and_source_set(rel)
    if path.name in {"build.gradle", "build.gradle.kts"}:
        parent = Path(rel).parent.as_posix()
        module = "" if parent == "." else parent
    suffix = path.suffix.lower()
    package_match = _PACKAGE_RE.search(text) if suffix in _CODE_EXTENSIONS else None
    package = package_match.group(1) if package_match else ""
    symbols: list[dict[str, str]] = []
    imports: list[str] = []
    identifiers: set[str] = set()
    android_classes: list[str] = []

    if suffix in _CODE_EXTENSIONS:
        imports = sorted(set(_IMPORT_RE.findall(text)))
        identifiers = set(_IDENTIFIER_RE.findall(text))
        for kind, name in _TYPE_DECL_RE.findall(text):
            symbols.append({
                "name": name,
                "fqn": f"{package}.{name}" if package else name,
                "kind": kind,
            })
    elif suffix == _XML_EXTENSION:
        manifest_package = ""
        package_match = _MANIFEST_PACKAGE_RE.search(text)
        if package_match:
            manifest_package = package_match.group(1)
        for value in _XML_CLASS_ATTR_RE.findall(text) + _XML_TAG_CLASS_RE.findall(text):
            expanded = _expand_android_class(value, manifest_package)
            if expanded:
                android_classes.append(expanded)

    resource_refs: list[tuple[str, str]] = []
    for match in _RESOURCE_RE.finditer(text):
        resource_type = match.group(1) or match.group(3)
        name = match.group(2) or match.group(4)
        if resource_type and name:
            resource_refs.append((resource_type, name))

    node = {
        "file": rel,
        "kind": "code" if suffix in _CODE_EXTENSIONS else "xml" if suffix == ".xml" else "config",
        "module": module,
        "source_set": source_set,
        "package": package,
        "symbols": symbols,
        "imports": imports,
        "analysis_state": analysis_state,
    }
    private = {
        "text": text,
        "identifiers": identifiers,
        "android_classes": android_classes,
        "resource_refs": resource_refs,
        "resource_defs": _xml_resource_definitions(rel, text) if suffix == _XML_EXTENSION else set(),
        "overlay_tail": overlay_tail,
    }
    return node, private


def build_relation_graph(repo_root: Path, files: Iterable[str]) -> dict[str, Any]:
    """Return a JSON-serializable file graph for the supplied repo-relative files."""
    repo_root = repo_root.resolve()
    ordered_files = list(dict.fromkeys(str(f).replace("\\", "/") for f in files))
    nodes: list[dict[str, Any]] = []
    private_by_file: dict[str, dict[str, Any]] = {}
    for rel in ordered_files:
        node, private = _inspect_file(repo_root, rel)
        nodes.append(node)
        private_by_file[rel] = private

    node_by_file = {node["file"]: node for node in nodes}
    fqn_files: dict[str, set[str]] = defaultdict(set)
    simple_files: dict[str, set[str]] = defaultdict(set)
    resources: dict[tuple[str, str, str], set[tuple[str, str]]] = defaultdict(set)
    overlay_groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    module_build_files: dict[str, str] = {}

    for node in nodes:
        rel = node["file"]
        for symbol in node["symbols"]:
            fqn_files[symbol["fqn"]].add(rel)
            simple_files[symbol["name"]].add(rel)
        resource = _resource_key(rel)
        if resource:
            module, source_set, resource_type, name = resource
            # values filenames are containers, not addressable resources; their
            # named child elements are indexed below.
            if resource_type != "values":
                resources[(module, resource_type, name)].add((source_set, rel))
        for resource_type, name in private_by_file[rel]["resource_defs"]:
            resources[(node["module"], resource_type, name)].add((node["source_set"], rel))
        tail = private_by_file[rel]["overlay_tail"]
        if tail:
            overlay_groups[(node["module"], tail)].append(rel)
        if Path(rel).name in {"build.gradle", "build.gradle.kts"}:
            module_build_files[node["module"]] = rel

    edge_data: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_edge(source: str, target: str, kind: str, evidence: str) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, kind)
        edge = edge_data.setdefault(key, {
            "source": source,
            "target": target,
            "kind": kind,
            "weight": _EDGE_WEIGHTS[kind],
            "evidence": [],
        })
        if evidence and evidence not in edge["evidence"] and len(edge["evidence"]) < 4:
            edge["evidence"].append(evidence[:240])

    def select_variant_targets(source_node: dict[str, Any], targets: set[str]) -> set[str]:
        """Prefer the source file's module/source set before accepting a global match."""
        if len(targets) <= 1:
            return targets
        same_module = {target for target in targets if node_by_file[target]["module"] == source_node["module"]}
        same_variant = {
            target for target in same_module
            if node_by_file[target]["source_set"] == source_node["source_set"]
        }
        main_variant = {
            target for target in same_module if node_by_file[target]["source_set"] == "main"
        }
        return same_variant or main_variant or same_module or targets

    for node in nodes:
        rel = node["file"]
        private = private_by_file[rel]
        for imported in node["imports"]:
            if imported.endswith(".*"):
                continue
            for target in sorted(select_variant_targets(node, fqn_files.get(imported, set()))):
                add_edge(rel, target, "exact_import", imported)

        for identifier in sorted(private["identifiers"]):
            same_package_fqn = f"{node['package']}.{identifier}" if node["package"] else identifier
            targets = fqn_files.get(same_package_fqn, set()) or simple_files.get(identifier, set())
            targets = select_variant_targets(node, targets)
            if len(targets) == 1:
                target = next(iter(targets))
                add_edge(rel, target, "unique_type_reference", identifier)

        for class_name in private["android_classes"]:
            targets = fqn_files.get(class_name, set())
            if not targets:
                targets = simple_files.get(class_name.rsplit(".", 1)[-1], set())
            targets = select_variant_targets(node, targets)
            if len(targets) == 1:
                add_edge(rel, next(iter(targets)), "android_component", class_name)

        for resource_type, name in private["resource_refs"]:
            candidates = resources.get((node["module"], resource_type, name), [])
            if not candidates and node["module"]:
                candidates = resources.get(("", resource_type, name), [])
            same_source_set = [item for item in candidates if item[0] == node["source_set"]]
            main_source_set = [item for item in candidates if item[0] == "main"]
            selected_resources = same_source_set or main_source_set or candidates
            for source_set, target in sorted(selected_resources):
                add_edge(rel, target, "android_resource", f"{resource_type}/{name} ({source_set})")

        if Path(rel).name in {"build.gradle", "build.gradle.kts"}:
            for dep in _PROJECT_DEP_RE.findall(private["text"]):
                target_module = dep.replace(":", "/")
                target = module_build_files.get(target_module)
                if target:
                    add_edge(rel, target, "gradle_project", f":{dep}")

    for (_module, tail), related in sorted(overlay_groups.items()):
        if len(related) < 2:
            continue
        ordered = sorted(related)
        main = next((rel for rel in ordered if node_by_file[rel]["source_set"] == "main"), ordered[0])
        for rel in ordered:
            if rel != main:
                add_edge(rel, main, "source_set_overlay", tail)

    edges = sorted(
        edge_data.values(),
        key=lambda edge: (-edge["weight"], edge["source"], edge["target"], edge["kind"]),
    )
    return {
        "schema_version": 1,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "files": len(nodes),
            "edges": len(edges),
            "files_not_fully_indexed": sorted(
                node["file"] for node in nodes if node["analysis_state"] != "complete"
            ),
            "edge_kinds": {
                kind: sum(1 for edge in edges if edge["kind"] == kind)
                for kind in sorted({edge["kind"] for edge in edges})
            },
        },
        "limitations": [
            "source-only relation hints; not compiler-resolved runtime reachability",
            "unique type references omit ambiguous same-name targets",
            "reflection, generated code, and dynamic dispatch require source verification",
        ],
    }


def adjacency(graph: dict[str, Any]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = defaultdict(dict)
    for edge in graph.get("edges", []):
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        weight = int(edge.get("weight", 1))
        if not source or not target:
            continue
        out[source][target] = out[source].get(target, 0) + weight
        out[target][source] = out[target].get(source, 0) + weight
    return dict(out)


def expand_from_files(graph: dict[str, Any], seeds: Iterable[str], depth: int) -> set[str]:
    """Return graph neighbors within ``depth`` undirected hops of ``seeds``."""
    found = set(seeds)
    if depth <= 0:
        return found
    links = adjacency(graph)
    queue = deque((seed, 0) for seed in found)
    while queue:
        current, current_depth = queue.popleft()
        if current_depth >= depth:
            continue
        for neighbor in links.get(current, {}):
            if neighbor in found:
                continue
            found.add(neighbor)
            queue.append((neighbor, current_depth + 1))
    return found


def cluster_items(
    items: list[dict[str, Any]], graph: dict[str, Any], batch_size: int, token_budget: int,
) -> list[list[dict[str, Any]]]:
    """Greedily batch files while preferring strongly related graph neighbors.

    Risk still selects each new seed.  Once a seed is chosen, relation weight is
    the primary score, which keeps callers/config/resources close when limits
    allow.  Every item is assigned exactly once.
    """
    by_file = {str(item["file"]): item for item in items}
    links = adjacency(graph)
    remaining = set(by_file)
    chunks: list[list[dict[str, Any]]] = []

    def risk_key(rel: str) -> tuple[int, str]:
        return (-int(by_file[rel].get("risk_score", 0)), rel)

    while remaining:
        seed = min(remaining, key=risk_key)
        selected: list[str] = [seed]
        remaining.remove(seed)
        used_tokens = int(by_file[seed].get("estimated_tokens", 0))

        while remaining and len(selected) < batch_size:
            related: list[tuple[int, int, str]] = []
            for rel in remaining:
                relation_weight = sum(links.get(rel, {}).get(member, 0) for member in selected)
                if relation_weight:
                    related.append((-relation_weight, -int(by_file[rel].get("risk_score", 0)), rel))
            if related:
                candidates = [entry[2] for entry in sorted(related)]
            else:
                candidates = sorted(remaining, key=risk_key)

            chosen = ""
            for rel in candidates:
                item_tokens = int(by_file[rel].get("estimated_tokens", 0))
                if used_tokens + item_tokens <= token_budget:
                    chosen = rel
                    break
            if not chosen:
                break
            selected.append(chosen)
            remaining.remove(chosen)
            used_tokens += int(by_file[chosen].get("estimated_tokens", 0))

        chunks.append([by_file[rel] for rel in selected])
    return chunks


def edges_for_batch(graph: dict[str, Any], files: Iterable[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    members = set(files)
    internal: list[dict[str, Any]] = []
    boundary: list[dict[str, Any]] = []
    for edge in graph.get("edges", []):
        source_in = edge.get("source") in members
        target_in = edge.get("target") in members
        if source_in and target_in:
            internal.append(edge)
        elif source_in or target_in:
            boundary.append(edge)
    return internal, boundary
