#!/usr/bin/env python3
"""
Dataset Archive Utility

Archives the current baseline dataset and prepares for a new version.
Automatically detects the next version number based on existing archives.

IMPORTANT: This tool NEVER deletes data. All dataset versions are preserved
in the archive. The prepare_new_version function only clears the active
directory AFTER successfully archiving the current version.

Usage:
    python -m src.utils.archive_dataset [--description "Fix description"]

Author: Cecilia Nothstein
"""

import json
import shutil
import re
from pathlib import Path
from datetime import datetime
from typing import Optional


# Paths relative to project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASELINE_DIR = PROJECT_ROOT / "data" / "03_baseline"
ARCHIVE_DIR = PROJECT_ROOT / "data" / "archive"


def get_current_version() -> Optional[str]:
    """Read current version from manifest.json."""
    manifest_path = BASELINE_DIR / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
            return manifest.get("version")
    return None


def get_latest_archive_version() -> int:
    """Find the highest version number in archive (b0, b1, b2, ...)."""
    if not ARCHIVE_DIR.exists():
        return -1

    max_version = -1
    for folder in ARCHIVE_DIR.iterdir():
        if folder.is_dir():
            match = re.match(r'^b(\d+)$', folder.name)
            if match:
                version_num = int(match.group(1))
                max_version = max(max_version, version_num)

    return max_version


def get_next_version() -> str:
    """Determine the next version number."""
    latest = get_latest_archive_version()
    return f"b{latest + 1}"


def archive_current(description: str = None) -> str:
    """
    Archive current baseline dataset.

    Args:
        description: Optional description for the archived version

    Returns:
        Path to archived version
    """
    current_version = get_current_version()
    if not current_version:
        raise ValueError("No manifest.json found in baseline directory")

    # Check if this version is already archived
    archive_path = ARCHIVE_DIR / current_version
    if archive_path.exists():
        raise ValueError(f"Version {current_version} already exists in archive")

    # Create archive directory
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    archive_path.mkdir(exist_ok=True)

    # Copy all JSON files to archive
    files_copied = []
    for json_file in BASELINE_DIR.glob("*.json"):
        dest = archive_path / json_file.name
        shutil.copy2(json_file, dest)
        files_copied.append(json_file.name)

    # Add archive metadata
    archive_meta = {
        "archived_at": datetime.now().isoformat(),
        "description": description or f"Archived version {current_version}",
        "files": files_copied
    }

    with open(archive_path / "_archive_meta.json", 'w') as f:
        json.dump(archive_meta, f, indent=2)

    print(f"Archived {current_version} to {archive_path}")
    print(f"Files: {', '.join(files_copied)}")

    return str(archive_path)


def verify_archived(version: str) -> bool:
    """Verify that a version exists in the archive."""
    archive_path = ARCHIVE_DIR / version
    if not archive_path.exists():
        return False
    # Check that essential files are archived
    required_files = ["manifest.json", "all_150_samples.json"]
    for f in required_files:
        if not (archive_path / f).exists():
            return False
    return True


def prepare_new_version(description: str = None, force_archive: bool = True) -> str:
    """
    Prepare baseline directory for new version.

    SAFETY: This function NEVER deletes data without archiving first.
    It verifies the current version is safely archived before clearing.

    Args:
        description: Description for the new version
        force_archive: If True (default), archive current version first

    Returns:
        New version string (e.g., "b3")

    Raises:
        ValueError: If current version is not archived and force_archive is False
    """
    current_version = get_current_version()

    # SAFETY CHECK: Ensure current version is archived
    if current_version and not verify_archived(current_version):
        if force_archive:
            print(f"Archiving {current_version} before preparing new version...")
            archive_current(description)
        else:
            raise ValueError(
                f"SAFETY: Version {current_version} is not archived! "
                f"Use --archive first or set force_archive=True"
            )

    # Verify archive was successful
    if current_version and not verify_archived(current_version):
        raise ValueError(
            f"SAFETY: Failed to verify archive of {current_version}. "
            f"Aborting to prevent data loss."
        )

    new_version = get_next_version()

    # Read current manifest as template
    manifest_path = BASELINE_DIR / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    else:
        manifest = {}

    # Update manifest for new version
    old_version = manifest.get("version", "unknown")
    manifest["version"] = new_version
    manifest["created_at"] = datetime.now().isoformat()
    manifest["description"] = description or f"Version {new_version}"
    manifest["previous_version"] = old_version

    # Clear old data files (keep manifest) - SAFE because we verified archive
    cleared_files = []
    for json_file in BASELINE_DIR.glob("*.json"):
        if json_file.name != "manifest.json":
            cleared_files.append(json_file.name)
            json_file.unlink()

    # Write updated manifest
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"Prepared for new version: {new_version}")
    print(f"Previous version: {old_version} (safely archived)")
    print(f"Cleared files: {', '.join(cleared_files)}")
    print(f"Manifest updated. Generate new data files now.")

    return new_version


def show_status():
    """Show current archive status."""
    print("\n=== Dataset Archive Status ===\n")

    # Current version
    current = get_current_version()
    print(f"Current active version: {current or 'None'}")
    print(f"Location: {BASELINE_DIR}")

    # List files in current
    if BASELINE_DIR.exists():
        files = list(BASELINE_DIR.glob("*.json"))
        print(f"Files: {len(files)}")
        for f in sorted(files):
            print(f"  - {f.name}")

    print()

    # Archived versions
    print("Archived versions:")
    if ARCHIVE_DIR.exists():
        for folder in sorted(ARCHIVE_DIR.iterdir()):
            if folder.is_dir() and folder.name.startswith('b'):
                meta_path = folder / "_archive_meta.json"
                if meta_path.exists():
                    with open(meta_path, 'r') as f:
                        meta = json.load(f)
                    desc = meta.get("description", "")
                    date = meta.get("archived_at", "")[:10]
                    print(f"  {folder.name}/ - {desc} ({date})")
                else:
                    files = len(list(folder.glob("*.json")))
                    print(f"  {folder.name}/ - {files} files")
    else:
        print("  (no archive yet)")

    # Next version
    next_ver = get_next_version()
    print(f"\nNext version will be: {next_ver}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Archive dataset versions"
    )
    parser.add_argument(
        '--archive',
        action='store_true',
        help='Archive current version'
    )
    parser.add_argument(
        '--prepare-new',
        action='store_true',
        help='Prepare for new version (archive current first)'
    )
    parser.add_argument(
        '--description',
        type=str,
        help='Description for archive or new version'
    )
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show archive status'
    )

    args = parser.parse_args()

    if args.status or (not args.archive and not args.prepare_new):
        show_status()
        return

    if args.archive:
        archive_current(args.description)

    if args.prepare_new:
        # prepare_new_version automatically archives if needed (safety check)
        prepare_new_version(args.description, force_archive=True)


if __name__ == "__main__":
    main()
