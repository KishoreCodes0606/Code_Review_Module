"""Parse sources.yaml into a flat list of SourceSpec objects."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import yaml


@dataclass
class SourceSpec:
    doc_id: str
    group: str
    doc_type: str
    file: str
    raw_url: str
    source_url: str
    license: str
    owasp: str = "general"
    cwe: list[str] = field(default_factory=list)
    language: str = "general"

    @property
    def local_rel_path(self) -> str:
        return f"{self.group}/{self.file}"


def load_sources(path: Path) -> list[SourceSpec]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    specs: list[SourceSpec] = []
    for group in data["groups"]:
        for item in group["items"]:
            page = item.get("page") or Path(item["file"]).stem
            specs.append(
                SourceSpec(
                    doc_id=item["id"],
                    group=group["name"],
                    doc_type=group["doc_type"],
                    file=item["file"],
                    raw_url=group["raw_base"] + quote(item["file"], safe="()"),
                    source_url=group["page_base"] + page + group.get("page_ext", ""),
                    license=group.get("license", ""),
                    owasp=item.get("owasp", "general"),
                    cwe=list(item.get("cwe", [])),
                    language=item.get("language", "general"),
                )
            )
    ids = [s.doc_id for s in specs]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Duplicate doc ids in sources.yaml: {sorted(dupes)}")
    return specs
