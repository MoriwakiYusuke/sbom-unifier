"""
SPDX field definitions for SBOM analysis.
"""

# SPDX field definitions
# (category, field_name, json_key, field_type, attribute)
# attribute: "required" | "optional" | "deprecated" | "omission"
#   - required: mandatory field per SPDX specification
#   - optional: optional field per SPDX specification
#   - deprecated: deprecated field
#   - omission: omitted section (Snippet, Other Licensing, Annotation) or conditional item
SPDX_FIELDS = [
    # Document Creation Information
    ("Document Creation Information", "SPDX Version", "spdxVersion", "document", "required"),
    ("Document Creation Information", "Data License", "dataLicense", "document", "required"),
    ("Document Creation Information", "SPDX Identifier", "SPDXID", "document", "required"),
    ("Document Creation Information", "Document Name", "name", "document", "required"),
    (
        "Document Creation Information",
        "SPDX Document Namespace",
        "documentNamespace",
        "document",
        "required",
    ),  # noqa: E501
    (
        "Document Creation Information",
        "External Document References",
        "externalDocumentRefs",
        "document",
        "omission",
    ),  # noqa: E501
    (
        "Document Creation Information",
        "License List Version",
        "creationInfo.licenseListVersion",
        "document",
        "optional",
    ),  # noqa: E501
    ("Document Creation Information", "Creator", "creationInfo.creators", "document", "required"),
    ("Document Creation Information", "Created", "creationInfo.created", "document", "required"),
    (
        "Document Creation Information",
        "Creator Comment",
        "creationInfo.comment",
        "document",
        "omission",
    ),  # noqa: E501
    ("Document Creation Information", "Document Comment", "comment", "document", "omission"),  # noqa: E501
    # Package Information
    ("Package Information", "Package Name", "name", "package", "required"),
    ("Package Information", "Package SPDX Identifier", "SPDXID", "package", "required"),
    ("Package Information", "Package Version", "versionInfo", "package", "optional"),
    ("Package Information", "Package File Name", "packageFileName", "package", "optional"),
    ("Package Information", "Package Supplier", "supplier", "package", "optional"),
    ("Package Information", "Package Originator", "originator", "package", "optional"),
    ("Package Information", "Package Download Location", "downloadLocation", "package", "required"),  # noqa: E501
    ("Package Information", "Files Analyzed", "filesAnalyzed", "package", "optional"),
    (
        "Package Information",
        "Package Verification Code",
        "packageVerificationCode",
        "package",
        "omission",
    ),  # noqa: E501
    ("Package Information", "Package Checksum", "checksums", "package", "optional"),  # noqa: E501
    ("Package Information", "Package Home Page", "homepage", "package", "optional"),  # noqa: E501
    ("Package Information", "Source Information", "sourceInfo", "package", "optional"),
    ("Package Information", "Concluded License", "licenseConcluded", "package", "optional"),
    (
        "Package Information",
        "All Licenses Information from Files",
        "licenseInfoFromFiles",
        "package",
        "omission",
    ),  # noqa: E501
    ("Package Information", "Declared License", "licenseDeclared", "package", "optional"),
    ("Package Information", "Comments on License", "licenseComments", "package", "omission"),  # noqa: E501
    ("Package Information", "Copyright Text", "copyrightText", "package", "optional"),
    ("Package Information", "Package Summary Description", "summary", "package", "omission"),  # noqa: E501
    ("Package Information", "Package Detailed Description", "description", "package", "omission"),  # noqa: E501
    ("Package Information", "Package Comment", "comment", "package", "omission"),  # noqa: E501
    ("Package Information", "External Reference", "externalRefs", "package", "optional"),
    (
        "Package Information",
        "External Reference Comment",
        "externalRefs.comment",
        "package",
        "omission",
    ),  # noqa: E501
    ("Package Information", "Package Attribution Text", "attributionTexts", "package", "optional"),  # noqa: E501
    (
        "Package Information",
        "Primary Package Purpose",
        "primaryPackagePurpose",
        "package",
        "optional",
    ),  # noqa: E501
    ("Package Information", "Release Date", "releaseDate", "package", "optional"),  # noqa: E501
    ("Package Information", "Built Date", "builtDate", "package", "optional"),  # unsupported item
    ("Package Information", "Valid Until Date", "validUntilDate", "package", "optional"),  # noqa: E501
    # File Information
    ("File Information", "File Name", "fileName", "file", "required"),
    ("File Information", "File SPDX Identifier", "SPDXID", "file", "required"),
    ("File Information", "File Type", "fileTypes", "file", "optional"),
    ("File Information", "File Checksum", "checksums", "file", "required"),
    ("File Information", "Concluded License", "licenseConcluded", "file", "optional"),
    ("File Information", "License Information in File", "licenseInfoInFiles", "file", "optional"),
    ("File Information", "Comments on License", "licenseComments", "file", "omission"),  # noqa: E501
    ("File Information", "Copyright Text", "copyrightText", "file", "optional"),
    (
        "File Information",
        "Artifact of Project Name (deprecated)",
        "artifactOf.name",
        "file",
        "deprecated",
    ),  # noqa: E501
    (
        "File Information",
        "Artifact of Project Homepage (deprecated)",
        "artifactOf.homepage",
        "file",
        "deprecated",
    ),  # noqa: E501
    (
        "File Information",
        "Artifact of Project Uniform Resource Identifier (deprecated)",
        "artifactOf.uri",
        "file",
        "deprecated",
    ),  # noqa: E501
    ("File Information", "File Comment", "comment", "file", "omission"),  # unsupported item
    ("File Information", "File Notice", "noticeText", "file", "omission"),  # unsupported item
    ("File Information", "File Contributor", "fileContributors", "file", "optional"),  # noqa: E501
    ("File Information", "File Attribution Text", "attributionTexts", "file", "optional"),  # noqa: E501
    (
        "File Information",
        "File Dependencies (deprecated)",
        "fileDependencies",
        "file",
        "deprecated",
    ),  # noqa: E501
    # Snippet Information (optional section -> omission)
    ("Snippet Information", "Snippet SPDX Identifier", "SPDXID", "snippet", "omission"),
    (
        "Snippet Information",
        "Snippet from File SPDX Identifier",
        "snippetFromFile",
        "snippet",
        "omission",
    ),  # noqa: E501
    (
        "Snippet Information",
        "Snippet Byte Range",
        "ranges.startPointer.offset",
        "snippet",
        "omission",
    ),  # noqa: E501
    (
        "Snippet Information",
        "Snippet Line Range",
        "ranges.startPointer.lineNumber",
        "snippet",
        "omission",
    ),  # noqa: E501
    ("Snippet Information", "Snippet Concluded License", "licenseConcluded", "snippet", "omission"),  # noqa: E501
    (
        "Snippet Information",
        "License Information in Snippet",
        "licenseInfoInSnippets",
        "snippet",
        "omission",
    ),  # noqa: E501
    (
        "Snippet Information",
        "Snippet Comments on License",
        "licenseComments",
        "snippet",
        "omission",
    ),  # noqa: E501
    ("Snippet Information", "Snippet Copyright Text", "copyrightText", "snippet", "omission"),
    ("Snippet Information", "Snippet Comment", "comment", "snippet", "omission"),
    ("Snippet Information", "Snippet Name", "name", "snippet", "omission"),
    ("Snippet Information", "Snippet Attribution Text", "attributionTexts", "snippet", "omission"),  # noqa: E501
    # Other Licensing Information (optional section -> omission)
    (
        "Other Licensing Information",
        "License Identifier",
        "licenseId",
        "extractedLicensingInfo",
        "omission",
    ),  # noqa: E501
    (
        "Other Licensing Information",
        "Extracted Text",
        "extractedText",
        "extractedLicensingInfo",
        "omission",
    ),  # noqa: E501
    ("Other Licensing Information", "License Name", "name", "extractedLicensingInfo", "omission"),
    (
        "Other Licensing Information",
        "License Cross Reference",
        "seeAlsos",
        "extractedLicensingInfo",
        "omission",
    ),  # noqa: E501
    (
        "Other Licensing Information",
        "License Comment",
        "comment",
        "extractedLicensingInfo",
        "omission",
    ),  # noqa: E501
    # Relationship Information
    ("Relationship Information", "Relationship", "relationshipType", "relationship", "required"),
    ("Relationship Information", "Relationship Comment", "comment", "relationship", "optional"),
    # Annotation Information (optional section -> omission)
    ("Annotation Information", "Annotator", "annotator", "annotation", "omission"),
    ("Annotation Information", "Annotation Date", "annotationDate", "annotation", "omission"),
    ("Annotation Information", "Annotation Type", "annotationType", "annotation", "omission"),
    (
        "Annotation Information",
        "SPDX Identifier Reference",
        "spdxElementId",
        "annotation",
        "omission",
    ),  # noqa: E501
    ("Annotation Information", "Annotation Comment", "comment", "annotation", "omission"),
    # Review Information (deprecated)
    (
        "Review Information (deprecated)",
        "Reviewer (deprecated)",
        "reviewer",
        "review",
        "deprecated",
    ),  # noqa: E501
    (
        "Review Information (deprecated)",
        "Review Date (deprecated)",
        "reviewDate",
        "review",
        "deprecated",
    ),  # noqa: E501
    (
        "Review Information (deprecated)",
        "Review Comment (deprecated)",
        "comment",
        "review",
        "deprecated",
    ),  # noqa: E501
]


# =============================================================================
# Conditional required fields and optional section definitions
# =============================================================================

# Non-mandatory sections (when section is absent, all fields are miss + omission attribute)
# Specified by field_type as key
# SPDX 2.3 spec: only Document Creation Information is Mandatory
# All of the following are Optional, zero or many:
#   - Package Information
#   - File Information
#   - Snippet Information
#   - Other Licensing Information
#   - Relationships
#   - Annotations
#   - Review (deprecated)
OPTIONAL_SECTIONS = {
    "package",
    "file",
    "snippet",
    "extractedLicensingInfo",
    "relationship",
    "annotation",
    "review",
}

# Note: OMISSION_SECTIONS and CONDITIONAL_REQUIRED are deprecated.
# Omitted sections (snippet, extractedLicensingInfo, annotation) and
# former conditional items (packageVerificationCode, licenseInfoFromFiles) are
# directly specified as "omission" in the SPDX_FIELDS attribute.


def get_excluded_field_names() -> set:
    """Return set of full_names to exclude from graphs (all non-required fields)."""
    return {f"{cat}|{name}" for cat, name, _, _, attr in SPDX_FIELDS if attr != "required"}


def get_deprecated_field_names() -> set:
    """Return set of full_names for deprecated fields."""
    return {f"{cat}|{name}" for cat, name, _, _, attr in SPDX_FIELDS if attr == "deprecated"}


def get_field_attribute(category: str, field_name: str) -> str:
    """Return the static attribute for a field."""
    for cat, name, _, _, attr in SPDX_FIELDS:
        if cat == category and name == field_name:
            return attr
    return "optional"


def get_field_attribute_map() -> dict:
    """Return a map of all field static attributes (full_name -> attribute)."""
    return {f"{cat}|{name}": attr for cat, name, _, _, attr in SPDX_FIELDS}


def get_field_count() -> dict:
    """Return field counts by category."""
    total = len(SPDX_FIELDS)
    excluded = sum(1 for _, _, _, _, attr in SPDX_FIELDS if attr != "required")
    deprecated = sum(1 for _, _, _, _, attr in SPDX_FIELDS if attr == "deprecated")
    return {
        "total": total,
        "excluded": excluded,
        "included": total - excluded,
        "deprecated": deprecated,
    }
