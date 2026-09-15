"""Read-only adapter for the vendored NIST CSF 2.0 OSCAL catalog.

The source document is intentionally retained unchanged in
``profiles/nist-csf-2.0-catalog.json``.  This module exposes only the small,
stable hierarchy the local UI needs; it does not reinterpret official outcome
text as executable product behavior.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


CATALOG_PATH = Path(__file__).resolve().parent / "profiles" / "nist-csf-2.0-catalog.json"
EXPECTED_FUNCTION_COUNT = 6
EXPECTED_CATEGORY_COUNT = 22
EXPECTED_SUBCATEGORY_COUNT = 106


def _part_prose(parts: List[Dict[str, Any]], name: str = "statement") -> str:
    for part in parts or []:
        if str(part.get("name") or "").strip().lower() == name:
            return str(part.get("prose") or "").strip()
    return ""


def _part_prose_list(parts: List[Dict[str, Any]], name: str) -> List[str]:
    """Return ordered prose parts without rewording the official catalog."""
    return [
        str(part.get("prose") or "").strip()
        for part in parts or []
        if str(part.get("name") or "").strip().lower() == name and str(part.get("prose") or "").strip()
    ]


def _is_withdrawn(item: Dict[str, Any]) -> bool:
    return any(
        str(prop.get("name") or "").strip().lower() == "status"
        and str(prop.get("value") or "").strip().lower() == "withdrawn"
        for prop in item.get("props") or []
    )


def load_official_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and validate the official CSF 2.0 hierarchy from vendored OSCAL."""
    source_path = Path(path or CATALOG_PATH)
    with source_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)

    catalog = document.get("catalog") or {}
    metadata = catalog.get("metadata") or {}
    functions: List[Dict[str, Any]] = []
    category_count = 0
    subcategory_count = 0

    for function in catalog.get("groups") or []:
        if str(function.get("class") or "").strip().lower() != "function":
            continue
        categories: List[Dict[str, Any]] = []
        for category in function.get("controls") or []:
            if str(category.get("class") or "").strip().lower() != "category" or _is_withdrawn(category):
                continue
            subcategories: List[Dict[str, Any]] = []
            for subcategory in category.get("controls") or []:
                if str(subcategory.get("class") or "").strip().lower() != "subcategory" or _is_withdrawn(subcategory):
                    continue
                subcategories.append(
                    {
                        "id": str(subcategory.get("id") or "").strip(),
                        "title": str(subcategory.get("title") or "").strip(),
                        "outcome": _part_prose(subcategory.get("parts") or []),
                        "implementation_examples": _part_prose_list(subcategory.get("parts") or [], "example"),
                    }
                )
            subcategory_count += len(subcategories)
            categories.append(
                {
                    "id": str(category.get("id") or "").strip(),
                    "title": str(category.get("title") or "").strip(),
                    "outcome": _part_prose(category.get("parts") or []),
                    "subcategories": subcategories,
                }
            )
        category_count += len(categories)
        functions.append(
            {
                "id": str(function.get("id") or "").strip(),
                "title": str(function.get("title") or "").strip(),
                "outcome": _part_prose(function.get("parts") or [], "overview"),
                "categories": categories,
            }
        )

    if len(functions) != EXPECTED_FUNCTION_COUNT:
        raise ValueError(f"Expected {EXPECTED_FUNCTION_COUNT} CSF Functions, found {len(functions)}.")
    if category_count != EXPECTED_CATEGORY_COUNT:
        raise ValueError(f"Expected {EXPECTED_CATEGORY_COUNT} CSF Categories, found {category_count}.")
    if subcategory_count != EXPECTED_SUBCATEGORY_COUNT:
        raise ValueError(f"Expected {EXPECTED_SUBCATEGORY_COUNT} CSF Subcategories, found {subcategory_count}.")

    return {
        "source_path": str(source_path),
        "catalog_title": str(metadata.get("title") or "NIST Cybersecurity Framework 2.0"),
        "catalog_version": str(metadata.get("version") or ""),
        "functions": functions,
    }


def find_official_subcategory(identifier: str, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Return one official subcategory with its containing Function/Category."""
    target = str(identifier or "").strip().upper()
    for function in load_official_catalog(path).get("functions") or []:
        for category in function.get("categories") or []:
            for subcategory in category.get("subcategories") or []:
                if subcategory.get("id", "").upper() == target:
                    return {
                        **subcategory,
                        "function_id": function["id"],
                        "function_title": function["title"],
                        "category_id": category["id"],
                        "category_title": category["title"],
                    }
    return None
