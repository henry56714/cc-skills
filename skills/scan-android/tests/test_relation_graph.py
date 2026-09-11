import tempfile
import unittest
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
from relation_graph import build_relation_graph, expand_from_files  # noqa: E402
from repo_map import (  # noqa: E402
    DEFAULT_MAP_TOKEN_BUDGET,
    RepoMap,
    _bounded_map,
    _mark_unsupported_navigation_files,
)


class RelationGraphTests(unittest.TestCase):
    def test_links_manifest_component_resource_and_source_set_overlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            files = {
                "app/src/main/AndroidManifest.xml": (
                    '<manifest package="com.example"><application>'
                    '<activity android:name=".MainActivity" xmlns:android="http://schemas.android.com/apk/res/android"/>'
                    "</application></manifest>"
                ),
                "app/src/main/java/com/example/MainActivity.kt": (
                    "package com.example\nclass MainActivity { val screen = R.layout.screen }\n"
                ),
                "app/src/main/res/layout/screen.xml": "<LinearLayout />\n",
                "app/src/debug/res/layout/screen.xml": "<LinearLayout />\n",
            }
            for rel, content in files.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            graph = build_relation_graph(repo, files)
            kinds = {edge["kind"] for edge in graph["edges"]}
            self.assertIn("android_component", kinds)
            self.assertIn("android_resource", kinds)
            self.assertIn("source_set_overlay", kinds)

            expanded = expand_from_files(
                graph, {"app/src/main/AndroidManifest.xml"}, depth=1,
            )
            self.assertIn("app/src/main/java/com/example/MainActivity.kt", expanded)

    def test_ambiguous_simple_type_is_not_linked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            files = {
                "app/src/main/java/client/Client.kt": (
                    "package client\nclass Client { val x: Api? = null }\n"
                ),
                "app/src/main/java/a/Api.kt": "package a\nclass Api\n",
                "app/src/main/java/b/Api.kt": "package b\nclass Api\n",
            }
            for rel, content in files.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            graph = build_relation_graph(repo, files)
            type_edges = [edge for edge in graph["edges"] if edge["kind"] == "unique_type_reference"]
            self.assertEqual(type_edges, [])

    def test_links_gradle_project_dependencies_by_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            files = {
                "app/build.gradle": "dependencies { implementation(project(':core')) }\n",
                "core/build.gradle": "plugins {}\n",
            }
            for rel, content in files.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            graph = build_relation_graph(repo, files)
            edges = [edge for edge in graph["edges"] if edge["kind"] == "gradle_project"]
            self.assertEqual(len(edges), 1)
            self.assertEqual(edges[0]["source"], "app/build.gradle")
            self.assertEqual(edges[0]["target"], "core/build.gradle")

    def test_links_named_values_resource_and_prefers_same_module_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            files = {
                "app/src/main/java/p/Screen.kt": (
                    "package p\nclass Screen { val api: Api? = null; val title = R.string.title }\n"
                ),
                "app/src/main/java/p/Api.kt": "package p\nclass Api\n",
                "other/src/main/java/q/Api.kt": "package q\nclass Api\n",
                "app/src/main/res/values/strings.xml": (
                    '<resources><string name="title">Title</string></resources>\n'
                ),
            }
            for rel, content in files.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            graph = build_relation_graph(repo, files)
            edges = {(edge["kind"], edge["source"], edge["target"]) for edge in graph["edges"]}
            self.assertIn((
                "unique_type_reference",
                "app/src/main/java/p/Screen.kt",
                "app/src/main/java/p/Api.kt",
            ), edges)
            self.assertIn((
                "android_resource",
                "app/src/main/java/p/Screen.kt",
                "app/src/main/res/values/strings.xml",
            ), edges)


class RepoMapSymbolTests(unittest.TestCase):
    def test_default_map_budget_matches_default_hunter_budget(self):
        self.assertEqual(DEFAULT_MAP_TOKEN_BUDGET, 24_000)
        skill = (SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn(
            "--budget <run_manifest.effective_hunt_policy.token_budget>",
            skill,
        )

    def test_native_and_web_sources_are_explicitly_unindexed(self):
        repo_map = RepoMap.__new__(RepoMap)
        repo_map._files_not_indexed = {}
        _mark_unsupported_navigation_files(
            repo_map, ["bridge.cpp", "page.js", "AndroidManifest.xml", "Main.kt"],
        )
        self.assertEqual(
            repo_map._files_not_indexed,
            {
                "bridge.cpp": "unsupported-navigation-language",
                "page.js": "unsupported-navigation-language",
            },
        )

    def _map(self) -> RepoMap:
        repo_map = RepoMap.__new__(RepoMap)
        repo_map._defs = [
            {"name": "save", "kind": "method", "file": "A.kt", "line": 3,
             "owner": "Alpha", "owner_fqn": "p.Alpha", "fqn": "p.Alpha#save"},
            {"name": "save", "kind": "method", "file": "B.kt", "line": 7,
             "owner": "Beta", "owner_fqn": "p.Beta", "fqn": "p.Beta#save"},
        ]
        repo_map._refs = [
            {"name": "save", "kind": "method", "file": "Caller.kt", "line": 9,
             "snippet": "Alpha.save()", "receiver": "Alpha", "enclosing": "run",
             "enclosing_type": "Caller", "enclosing_symbol": "p.Caller#run"},
            {"name": "save", "kind": "method", "file": "Other.kt", "line": 4,
             "snippet": "repo.save()", "receiver": "repo", "enclosing": "run",
             "enclosing_type": "Other", "enclosing_symbol": "p.Other#run"},
        ]
        return repo_map

    def test_class_method_definition_filters_owner(self):
        result = self._map().get_definition("Alpha#save")
        self.assertEqual([item["file"] for item in result], ["A.kt"])

    def test_class_method_callers_label_ambiguous_name_matches(self):
        result = self._map().get_callers("Alpha#save")
        self.assertEqual(result[0]["confidence"], "high")
        self.assertEqual(result[0]["matched_by"], "explicit-receiver")
        self.assertEqual(result[1]["confidence"], "ambiguous")

    def test_unique_method_name_does_not_resolve_wrong_variable_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "Caller.java").write_text(
                "class Caller { Runnable worker; void go() { worker.run(); } }"
            )
            repo_map = RepoMap.__new__(RepoMap)
            repo_map.repo = repo
            repo_map._receiver_types = {}
            repo_map._defs = [{
                "name": "run", "kind": "method", "file": "WatchdogThread.java",
                "line": 2, "owner": "WatchdogThread", "owner_fqn": "p.WatchdogThread",
                "fqn": "p.WatchdogThread#run", "sig": "void run()",
            }]
            repo_map._refs = [{
                "name": "run", "kind": "method", "file": "Caller.java", "line": 1,
                "receiver": "worker", "enclosing_type": "Caller",
                "enclosing_symbol": "Caller#go", "snippet": "worker.run();",
            }]
            rendered = repo_map.focused_map(["Caller.java"], 1000)
            self.assertNotIn("p.WatchdogThread#run", rendered)

    def test_total_map_budget_includes_unbounded_skeleton_prefix(self):
        self.assertLessEqual(len(_bounded_map("x" * 1000, 10)), 40)


if __name__ == "__main__":
    unittest.main()
