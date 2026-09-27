from __future__ import annotations

import json
from pathlib import Path

from .models import ProjectInfo
from .utils import SOURCE_EXTENSIONS, is_ignored


class ProjectScanner:
    """Finds Next.js project metadata and source files."""

    def scan(self, root: Path) -> ProjectInfo:
        root = root.resolve()
        package_json = self._read_package_json(root)
        next_version = self._detect_next_version(package_json)
        has_next_config = any(
            (root / name).exists()
            for name in (
                "next.config.js",
                "next.config.mjs",
                "next.config.ts",
                "next.config.cjs",
            )
        )
        source_files = self._collect_source_files(root)
        return ProjectInfo(
            root=root,
            is_next_project=bool(next_version or has_next_config),
            next_version=next_version,
            has_app_router=(root / "app").exists() or (root / "src" / "app").exists(),
            has_pages_router=(root / "pages").exists() or (root / "src" / "pages").exists(),
            source_files=source_files,
            package_json=package_json,
        )

    def _read_package_json(self, root: Path) -> dict:
        package_path = root / "package.json"
        if not package_path.exists():
            return {}
        try:
            return json.loads(package_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _detect_next_version(self, package_json: dict) -> str | None:
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = package_json.get(section, {})
            if isinstance(deps, dict) and "next" in deps:
                return str(deps["next"])
        return None

    def _collect_source_files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        for path in root.rglob("*"):
            if path.is_dir() or is_ignored(path.relative_to(root)):
                continue
            if path.suffix in SOURCE_EXTENSIONS:
                files.append(path)
        return sorted(files)
