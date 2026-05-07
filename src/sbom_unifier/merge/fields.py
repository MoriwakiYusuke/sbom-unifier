"""Declarations of which SPDX fields are subject to merge supplementation."""

from __future__ import annotations

# Document-level fields whose missing/NOASSERTION values may be filled from sources.
DOCUMENT_FIELDS: list[str] = [
    "spdxVersion",
    "dataLicense",
    "SPDXID",
    "name",
    "documentNamespace",
    "externalDocumentRefs",
    "comment",
]

# Package-level simple fields.
PACKAGE_SIMPLE_FIELDS: list[str] = [
    "name",
    "SPDXID",
    "versionInfo",
    "packageFileName",
    "supplier",
    "originator",
    "downloadLocation",
    "filesAnalyzed",
    "homepage",
    "sourceInfo",
    "licenseConcluded",
    "licenseDeclared",
    "licenseComments",
    "copyrightText",
    "summary",
    "description",
    "comment",
    "primaryPackagePurpose",
    "releaseDate",
    "builtDate",
    "validUntilDate",
]

# File-level simple fields.
FILE_SIMPLE_FIELDS: list[str] = [
    "licenseConcluded",
    "copyrightText",
    "comment",
    "noticeText",
]

# File-level list fields whose values are unioned across sources.
FILE_LIST_FIELDS: list[str] = [
    "fileTypes",
    "licenseInfoInFiles",
    "attributionTexts",
]

# Values treated as "unset" for merge purposes.
INVALID_VALUES: tuple = (None, "", "NOASSERTION", "NONE")
