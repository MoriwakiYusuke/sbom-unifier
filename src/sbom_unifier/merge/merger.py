"""SBOM merge logic: package, file, and relationship merging by PURL/filename."""

import copy
from datetime import UTC, datetime

from ..config import SCRIPT_CREATOR, TARGET_SPDX_VERSION
from .fields import (
    DOCUMENT_FIELDS,
    FILE_LIST_FIELDS,
    FILE_SIMPLE_FIELDS,
    INVALID_VALUES,
    PACKAGE_SIMPLE_FIELDS,
)
from .utils import get_purl_from_package


def _get_main_package_spdx_id(sbom_data: dict) -> str | None:
    """Locate the top-level package's SPDXID via the DESCRIBES relationship."""
    if "relationships" in sbom_data:
        for rel in sbom_data["relationships"]:
            if (
                rel.get("relationshipType") == "DESCRIBES"
                and rel.get("spdxElementId") == "SPDXRef-DOCUMENT"
            ):
                return rel.get("relatedSpdxElement")
    return None


def _create_annotation(comment: str, spdx_element_id: str | None = None) -> dict:
    """Create an annotation.

    Args:
        comment: The annotation comment text.
        spdx_element_id: The SPDX ID of the element being annotated (e.g. a package SPDXID).
    """
    annotation = {
        "annotationDate": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "annotationType": "OTHER",
        "annotator": SCRIPT_CREATOR,
        "comment": comment,
    }
    if spdx_element_id:
        annotation["spdxElementId"] = spdx_element_id
    return annotation


def _is_same_external_ref(ref1: dict, ref2: dict) -> bool:
    """Deduplicate externalRefs by full-field match."""
    return (
        ref1.get("referenceCategory") == ref2.get("referenceCategory")
        and ref1.get("referenceType") == ref2.get("referenceType")
        and ref1.get("referenceLocator") == ref2.get("referenceLocator")
    )


def _is_same_checksum(cs1: dict, cs2: dict) -> bool:
    """Deduplicate checksums by algorithm + value."""
    return cs1.get("algorithm") == cs2.get("algorithm") and cs1.get("checksumValue") == cs2.get(
        "checksumValue"
    )


def _build_purl_to_spdxid_map(sbom_data: dict) -> dict:
    """Build a PURL -> SPDXID map."""
    purl_map = {}
    for pkg in sbom_data.get("packages", []):
        purl = get_purl_from_package(pkg)
        if purl:
            purl_map[purl] = pkg.get("SPDXID")
    return purl_map


def _build_spdxid_to_purl_map(sbom_data: dict) -> dict:
    """Build a SPDXID -> PURL map."""
    spdxid_map = {}
    for pkg in sbom_data.get("packages", []):
        spdxid = pkg.get("SPDXID")
        purl = get_purl_from_package(pkg)
        if spdxid and purl:
            spdxid_map[spdxid] = purl
    return spdxid_map


def merge_package_info(base_pkg: dict, source_pkg: dict, source_tool_name: str) -> dict:
    """Merge existing package info from source. All fields are eligible for supplementation.

    Returns:
        dict: Summary of supplementation results.
    """
    results = {
        "fields_updated": 0,
        "fields_conflict": 0,
        "refs_added": 0,
        "annotations_added": 0,
    }
    updated_fields = []

    # --- Simple field supplementation ---
    for field in PACKAGE_SIMPLE_FIELDS:
        base_val = base_pkg.get(field)
        source_val = source_pkg.get(field)

        # Skip if source has no valid value
        if source_val in INVALID_VALUES:
            continue

        # Supplement (base is empty or NOASSERTION)
        if base_val in INVALID_VALUES:
            base_pkg[field] = source_val
            updated_fields.append(field)
            results["fields_updated"] += 1

        # Conflict (base and source have different valid values)
        elif base_val != source_val:
            results["fields_conflict"] += 1
            # Add a warning annotation
            annotation = _create_annotation(
                f"WARNING: Conflict in '{field}'. Kept '{base_val}'."
                f" Ignored '{source_val}' from {source_tool_name}.",
                base_pkg.get("SPDXID"),
            )
            base_pkg.setdefault("annotations", []).append(annotation)

    # --- externalRefs supplementation ---
    if "externalRefs" in source_pkg:
        base_refs = base_pkg.setdefault("externalRefs", [])
        for new_ref in source_pkg["externalRefs"]:
            # Deduplication check (all fields must match)
            is_duplicate = any(_is_same_external_ref(existing, new_ref) for existing in base_refs)
            if not is_duplicate:
                base_refs.append(copy.deepcopy(new_ref))
                results["refs_added"] += 1

    # --- checksums supplementation ---
    if "checksums" in source_pkg:
        base_checksums = base_pkg.setdefault("checksums", [])
        for new_cs in source_pkg["checksums"]:
            is_duplicate = any(_is_same_checksum(existing, new_cs) for existing in base_checksums)
            if not is_duplicate:
                base_checksums.append(copy.deepcopy(new_cs))

    # --- annotations supplementation ---
    if "annotations" in source_pkg:
        base_annotations = base_pkg.setdefault("annotations", [])
        existing_comments = {ann.get("comment") for ann in base_annotations}
        for new_ann in source_pkg["annotations"]:
            if new_ann.get("comment") not in existing_comments:
                base_annotations.append(copy.deepcopy(new_ann))
                existing_comments.add(new_ann.get("comment"))
                results["annotations_added"] += 1

    # --- attributionTexts supplementation ---
    if "attributionTexts" in source_pkg:
        base_attr = base_pkg.setdefault("attributionTexts", [])
        for text in source_pkg["attributionTexts"]:
            if text not in base_attr:
                base_attr.append(text)

    # --- licenseInfoFromFiles supplementation ---
    if "licenseInfoFromFiles" in source_pkg:
        base_info = base_pkg.setdefault("licenseInfoFromFiles", [])
        for info in source_pkg["licenseInfoFromFiles"]:
            if info not in base_info:
                base_info.append(info)

    # --- packageVerificationCode supplementation ---
    if "packageVerificationCode" in source_pkg:
        if "packageVerificationCode" not in base_pkg:
            base_pkg["packageVerificationCode"] = copy.deepcopy(
                source_pkg["packageVerificationCode"]
            )

    # --- Summary annotation when fields were supplemented ---
    if updated_fields:
        annotation = _create_annotation(
            f"Fields ({', '.join(updated_fields)}) were supplemented by {source_tool_name}.",
            base_pkg.get("SPDXID"),
        )
        base_pkg.setdefault("annotations", []).append(annotation)

    return results


def merge_document_info(base_data: dict, source_data: dict, source_tool_name: str) -> dict:
    """Merge document-level information."""
    results = {
        "fields_updated": 0,
        "creators_added": 0,
    }
    updated_fields = []

    # --- Simple field supplementation ---
    for field in DOCUMENT_FIELDS:
        if field == "externalDocumentRefs":
            continue  # Handled separately below

        base_val = base_data.get(field)
        source_val = source_data.get(field)

        if source_val in INVALID_VALUES:
            continue

        if base_val in INVALID_VALUES:
            base_data[field] = source_val
            updated_fields.append(field)
            results["fields_updated"] += 1

    # --- externalDocumentRefs supplementation ---
    if "externalDocumentRefs" in source_data:
        base_refs = base_data.setdefault("externalDocumentRefs", [])
        for new_ref in source_data["externalDocumentRefs"]:
            # Deduplication by full-field equality
            is_duplicate = any(existing == new_ref for existing in base_refs)
            if not is_duplicate:
                base_refs.append(copy.deepcopy(new_ref))

    # --- creationInfo field processing ---
    if "creationInfo" in source_data:
        base_creation_info = base_data.setdefault("creationInfo", {})

        # --- created field: keep earliest timestamp (or first available) ---
        source_created = source_data["creationInfo"].get("created")
        base_created = base_creation_info.get("created")
        if source_created and source_created not in INVALID_VALUES:
            if base_created in INVALID_VALUES or not base_created:
                # If base has no creation date, adopt from source
                base_creation_info["created"] = source_created
            # Note: when creation dates differ across tools, we keep the base's first date
            # (whether to update to latest, keep oldest, or record all is requirement-dependent)

        # --- licenseListVersion supplementation ---
        source_lic_ver = source_data["creationInfo"].get("licenseListVersion")
        base_lic_ver = base_creation_info.get("licenseListVersion")
        if source_lic_ver and source_lic_ver not in INVALID_VALUES:
            if base_lic_ver in INVALID_VALUES or not base_lic_ver:
                base_creation_info["licenseListVersion"] = source_lic_ver

        # --- creators consolidation ---
        if "creators" in source_data["creationInfo"]:
            base_creators = base_creation_info.setdefault("creators", [])
            for creator in source_data["creationInfo"]["creators"]:
                if creator not in base_creators:
                    base_creators.append(creator)
                    results["creators_added"] += 1

    return results


def add_missing_packages_and_relationships(
    base_data: dict, source_data: dict, source_tool_name: str
) -> tuple[int, int]:
    """Add packages and relationships present in source but not in base, deduplicated by PURL."""
    new_packages_added = 0
    new_relationships_added = 0

    if "packages" not in source_data:
        return 0, 0

    main_package_spdx_id = _get_main_package_spdx_id(base_data)

    if not main_package_spdx_id:
        print("   Warning: Could not find main package ID. Cannot add relationships.")

    # Build the base PURL set
    base_pkg_purls = set()
    for pkg in base_data.get("packages", []):
        purl = get_purl_from_package(pkg)
        if purl:
            base_pkg_purls.add(purl)

    for source_pkg in source_data.get("packages", []):
        source_purl = get_purl_from_package(source_pkg)

        # Only add if the PURL exists and is not already in the base SBOM
        if source_purl and source_purl not in base_pkg_purls:
            # Copy the new package
            new_pkg = copy.deepcopy(source_pkg)

            # Record the source tool as an annotation
            annotation = _create_annotation(
                f"Package (purl: {source_purl}) added from {source_tool_name}.",
                new_pkg.get("SPDXID"),
            )
            new_pkg.setdefault("annotations", []).append(annotation)

            # Fill mandatory SPDX fields with 'NOASSERTION' if absent
            new_pkg.setdefault("licenseConcluded", "NOASSERTION")
            new_pkg.setdefault("licenseDeclared", "NOASSERTION")
            new_pkg.setdefault("copyrightText", "NOASSERTION")

            # Append to packages list
            base_data.setdefault("packages", []).append(new_pkg)
            base_pkg_purls.add(source_purl)
            new_packages_added += 1

            # Add parent/child relationship to relationships
            new_pkg_spdx_id = new_pkg.get("SPDXID")
            if main_package_spdx_id and new_pkg_spdx_id:
                for source_rel in source_data.get("relationships", []):
                    if source_rel.get("relatedSpdxElement") == source_pkg.get("SPDXID"):
                        new_relationship = {
                            "spdxElementId": main_package_spdx_id,
                            "relatedSpdxElement": new_pkg_spdx_id,
                            "relationshipType": source_rel.get("relationshipType", "CONTAINS"),
                            "comment": f"Relationship added from {source_tool_name}.",
                        }

                        # Deduplication check
                        is_duplicate = any(
                            rel.get("spdxElementId") == new_relationship["spdxElementId"]
                            and rel.get("relatedSpdxElement")
                            == new_relationship["relatedSpdxElement"]
                            and rel.get("relationshipType") == new_relationship["relationshipType"]
                            for rel in base_data.get("relationships", [])
                        )

                        if not is_duplicate:
                            base_data.setdefault("relationships", []).append(new_relationship)
                            new_relationships_added += 1

    return new_packages_added, new_relationships_added


def _normalize_filename(filename: str) -> str:
    """Normalize a filename (strip ./ prefix)."""
    if filename.startswith("./"):
        return filename[2:]
    return filename.lstrip("/")


def _build_file_index(files: list[dict]) -> dict[str, int]:
    """Build a map: normalized filename -> index in files array."""
    index = {}
    for i, file_entry in enumerate(files):
        normalized = _normalize_filename(file_entry.get("fileName", ""))
        if normalized:
            index[normalized] = i
    return index


def merge_file_info(base_file: dict, source_file: dict, source_tool_name: str) -> dict:
    """Supplement an existing file entry's info from a source.

    Returns:
        dict: Summary of supplementation results.
    """
    results = {
        "fields_updated": 0,
        "fields_conflict": 0,
    }
    updated_fields = []

    # --- Simple field supplementation ---
    for field in FILE_SIMPLE_FIELDS:
        base_val = base_file.get(field)
        source_val = source_file.get(field)

        if source_val in INVALID_VALUES:
            continue

        if base_val in INVALID_VALUES:
            base_file[field] = source_val
            updated_fields.append(field)
            results["fields_updated"] += 1
        elif base_val != source_val:
            results["fields_conflict"] += 1
            annotation = _create_annotation(
                f"WARNING: Conflict in '{field}'. Kept '{base_val}'."
                f" Ignored '{source_val}' from {source_tool_name}.",
                base_file.get("SPDXID"),
            )
            base_file.setdefault("annotations", []).append(annotation)

    # --- List field supplementation ---
    for field in FILE_LIST_FIELDS:
        source_vals = source_file.get(field, [])
        if not source_vals:
            continue
        # Skip if all source values are invalid
        if all(v in INVALID_VALUES for v in source_vals):
            continue

        base_vals = base_file.get(field, [])
        # Overwrite if base has only invalid values
        if not base_vals or all(v in INVALID_VALUES for v in base_vals):
            base_file[field] = copy.deepcopy(source_vals)
            updated_fields.append(field)
            results["fields_updated"] += 1
        else:
            # Both have valid values: append elements not already in base
            for val in source_vals:
                if val not in INVALID_VALUES and val not in base_vals:
                    base_vals.append(val)

    # --- checksums supplementation ---
    if "checksums" in source_file:
        base_checksums = base_file.setdefault("checksums", [])
        for new_cs in source_file["checksums"]:
            is_duplicate = any(_is_same_checksum(existing, new_cs) for existing in base_checksums)
            if not is_duplicate:
                base_checksums.append(copy.deepcopy(new_cs))

    # --- annotations supplementation ---
    if "annotations" in source_file:
        base_annotations = base_file.setdefault("annotations", [])
        existing_comments = {ann.get("comment") for ann in base_annotations}
        for new_ann in source_file["annotations"]:
            if new_ann.get("comment") not in existing_comments:
                base_annotations.append(copy.deepcopy(new_ann))
                existing_comments.add(new_ann.get("comment"))

    # --- Summary annotation when fields were supplemented ---
    if updated_fields:
        annotation = _create_annotation(
            f"File fields ({', '.join(updated_fields)}) were supplemented by {source_tool_name}.",
            base_file.get("SPDXID"),
        )
        base_file.setdefault("annotations", []).append(annotation)

    return results


def merge_files(
    base_data: dict,
    source_data: dict,
    source_tool_name: str,
    add_missing_files: bool = True,
) -> dict:
    """Merge file section. Identify same files by normalized name; supplement existing entries;
    optionally add new files; maintain SPDXID consistency for relationships.

    Returns:
        dict: Summary of merge results.
    """
    results = {
        "files_merged": 0,
        "files_added": 0,
        "file_fields_updated": 0,
        "file_fields_conflict": 0,
        "file_relationships_added": 0,
    }

    source_files = source_data.get("files", [])
    if not source_files:
        return results

    base_files = base_data.setdefault("files", [])
    base_file_index = _build_file_index(base_files)

    # Source SPDXID -> Base SPDXID mapping (for relationship translation)
    source_to_base_spdxid = {}

    for source_file in source_files:
        source_filename = source_file.get("fileName", "")
        normalized = _normalize_filename(source_filename)

        if normalized in base_file_index:
            # Pattern A: same file exists -> supplement info
            base_idx = base_file_index[normalized]
            base_file = base_files[base_idx]

            merge_result = merge_file_info(base_file, source_file, source_tool_name)
            results["files_merged"] += 1
            results["file_fields_updated"] += merge_result["fields_updated"]
            results["file_fields_conflict"] += merge_result["fields_conflict"]

            # Record SPDXID mapping
            source_spdxid = source_file.get("SPDXID")
            base_spdxid = base_file.get("SPDXID")
            if source_spdxid and base_spdxid:
                source_to_base_spdxid[source_spdxid] = base_spdxid
        else:
            if not add_missing_files:
                continue

            # Pattern B: new file -> add it
            new_file = copy.deepcopy(source_file)
            # Normalize filename to base convention (./ prefix)
            if not new_file["fileName"].startswith("./"):
                new_file["fileName"] = "./" + new_file["fileName"]

            annotation = _create_annotation(
                f"File added from {source_tool_name}.", new_file.get("SPDXID")
            )
            new_file.setdefault("annotations", []).append(annotation)

            base_files.append(new_file)
            base_file_index[normalized] = len(base_files) - 1
            results["files_added"] += 1

            # Preserve SPDXID as-is
            source_spdxid = source_file.get("SPDXID")
            if source_spdxid:
                source_to_base_spdxid[source_spdxid] = new_file.get("SPDXID")

    # --- Merge file-related relationships ---
    existing_rels = set()
    for rel in base_data.get("relationships", []):
        key = (rel.get("spdxElementId"), rel.get("relatedSpdxElement"), rel.get("relationshipType"))
        existing_rels.add(key)

    for source_rel in source_data.get("relationships", []):
        source_element_id = source_rel.get("spdxElementId")
        source_related_id = source_rel.get("relatedSpdxElement")
        rel_type = source_rel.get("relationshipType")

        if rel_type == "DESCRIBES":
            continue

        # Only process relationships that involve a file SPDXID
        element_is_file = source_element_id in source_to_base_spdxid
        related_is_file = source_related_id in source_to_base_spdxid

        if not element_is_file and not related_is_file:
            continue

        # Translate SPDXIDs (use file mapping for files; PURL-based for packages)
        base_element_id = source_to_base_spdxid.get(source_element_id, source_element_id)
        base_related_id = source_to_base_spdxid.get(source_related_id, source_related_id)

        # Attempt PURL-based translation for package SPDXIDs
        if base_element_id == source_element_id:
            # PURL-based translation
            source_spdxid_to_purl = _build_spdxid_to_purl_map(source_data)
            base_purl_to_spdxid = _build_purl_to_spdxid_map(base_data)
            purl = source_spdxid_to_purl.get(source_element_id)
            if purl:
                mapped = base_purl_to_spdxid.get(purl)
                if mapped:
                    base_element_id = mapped

        if base_related_id == source_related_id:
            source_spdxid_to_purl = _build_spdxid_to_purl_map(source_data)
            base_purl_to_spdxid = _build_purl_to_spdxid_map(base_data)
            purl = source_spdxid_to_purl.get(source_related_id)
            if purl:
                mapped = base_purl_to_spdxid.get(purl)
                if mapped:
                    base_related_id = mapped

        key = (base_element_id, base_related_id, rel_type)
        if key in existing_rels:
            continue

        new_rel = {
            "spdxElementId": base_element_id,
            "relatedSpdxElement": base_related_id,
            "relationshipType": rel_type,
        }
        comment = source_rel.get("comment")
        if comment:
            new_rel["comment"] = comment
        else:
            new_rel["comment"] = f"File relationship added from {source_tool_name}."

        base_data.setdefault("relationships", []).append(new_rel)
        existing_rels.add(key)
        results["file_relationships_added"] += 1

    return results


def merge_transitive_relationships(
    base_data: dict, source_data: dict, source_tool_name: str
) -> int:
    """Merge transitive (package-to-package) relationships.
    Translate source SPDXIDs to base SPDXIDs via PURL.

    Returns:
        int: Number of relationships added.
    """
    relationships_added = 0

    # Build source SPDXID -> PURL map
    source_spdxid_to_purl = _build_spdxid_to_purl_map(source_data)

    # Build base PURL -> SPDXID map
    base_purl_to_spdxid = _build_purl_to_spdxid_map(base_data)

    # Build a set of existing relationships for deduplication
    existing_rels = set()
    for rel in base_data.get("relationships", []):
        key = (rel.get("spdxElementId"), rel.get("relatedSpdxElement"), rel.get("relationshipType"))
        existing_rels.add(key)

    # Process all relationships from source
    for source_rel in source_data.get("relationships", []):
        source_element_id = source_rel.get("spdxElementId")
        source_related_id = source_rel.get("relatedSpdxElement")
        rel_type = source_rel.get("relationshipType")

        # Skip DESCRIBES — it is a document-level relationship
        if rel_type == "DESCRIBES":
            continue

        # Translate source SPDXIDs to PURLs
        source_element_purl = source_spdxid_to_purl.get(source_element_id)
        source_related_purl = source_spdxid_to_purl.get(source_related_id)

        # Skip if either PURL cannot be resolved
        if not source_element_purl or not source_related_purl:
            continue

        # Translate PURLs to base SPDXIDs
        base_element_id = base_purl_to_spdxid.get(source_element_purl)
        base_related_id = base_purl_to_spdxid.get(source_related_purl)

        # Skip if either ID is not present in base
        if not base_element_id or not base_related_id:
            continue

        # Deduplication check
        key = (base_element_id, base_related_id, rel_type)
        if key in existing_rels:
            continue

        # Add new relationship
        new_rel = {
            "spdxElementId": base_element_id,
            "relatedSpdxElement": base_related_id,
            "relationshipType": rel_type,
            "comment": f"Transitive relationship added from {source_tool_name}.",
        }
        base_data.setdefault("relationships", []).append(new_rel)
        existing_rels.add(key)
        relationships_added += 1

    return relationships_added


def merge_sbom(
    base_data: dict,
    source_data: dict,
    source_tool_name: str,
    add_missing_packages: bool = True,
    add_missing_files: bool = True,
) -> dict:
    """Merge a single source SBOM into the base SBOM.

    Args:
        base_data: The base SBOM (mutated in place).
        source_data: The source SBOM to merge from.
        source_tool_name: Name of the tool that produced the source SBOM.
        add_missing_packages: Whether to add packages present in source but absent in base.
        add_missing_files: Whether to add files present in source but absent in base.

    Returns:
        dict: Summary of merge results.
    """
    results = {
        "packages_merged": 0,
        "packages_added": 0,
        "files_merged": 0,
        "files_added": 0,
        "relationships_added": 0,
        "fields_updated": 0,
        "fields_conflict": 0,
        "refs_added": 0,
        "annotations_added": 0,
        "creators_added": 0,
    }

    # --- Document-level merge ---
    doc_results = merge_document_info(base_data, source_data, source_tool_name)
    results["fields_updated"] += doc_results["fields_updated"]
    results["creators_added"] += doc_results["creators_added"]

    # --- Package-level merge ---
    # Index source packages by PURL
    source_pkg_map = {}
    for pkg in source_data.get("packages", []):
        purl = get_purl_from_package(pkg)
        if purl:
            source_pkg_map[purl] = pkg

    # Supplement base packages
    for base_pkg in base_data.get("packages", []):
        purl = get_purl_from_package(base_pkg)
        if purl and purl in source_pkg_map:
            pkg_results = merge_package_info(base_pkg, source_pkg_map[purl], source_tool_name)
            results["packages_merged"] += 1
            results["fields_updated"] += pkg_results["fields_updated"]
            results["fields_conflict"] += pkg_results["fields_conflict"]
            results["refs_added"] += pkg_results["refs_added"]
            results["annotations_added"] += pkg_results["annotations_added"]

    # --- Add missing packages ---
    if add_missing_packages:
        new_pkgs, new_rels = add_missing_packages_and_relationships(
            base_data, source_data, source_tool_name
        )
        results["packages_added"] += new_pkgs
        results["relationships_added"] += new_rels

    # --- Merge transitive (package-to-package) relationships ---
    transitive_rels = merge_transitive_relationships(base_data, source_data, source_tool_name)
    results["relationships_added"] += transitive_rels

    # --- File section merge ---
    file_results = merge_files(
        base_data,
        source_data,
        source_tool_name,
        add_missing_files=add_missing_files,
    )
    results["files_merged"] += file_results["files_merged"]
    results["files_added"] += file_results["files_added"]
    results["fields_updated"] += file_results["file_fields_updated"]
    results["fields_conflict"] += file_results["file_fields_conflict"]
    results["relationships_added"] += file_results["file_relationships_added"]

    return results


def finalize_sbom(base_data: dict) -> None:
    """Finalize: stamp target SPDX version and ensure script creator is recorded."""
    base_data["spdxVersion"] = TARGET_SPDX_VERSION
    creators_list = base_data.setdefault("creationInfo", {}).setdefault("creators", [])
    if SCRIPT_CREATOR not in creators_list:
        creators_list.append(SCRIPT_CREATOR)
