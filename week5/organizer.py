#!/usr/bin/env python3
"""
Smart Downloads Organizer
Automatically categorizes and organizes files by type
Generates JSON and text reports
"""

from pathlib import Path
import shutil
import json
from datetime import datetime
import sys

# Category mapping - extensions grouped by file type
CATEGORIES = {
    "documents": ["pdf", "doc", "docx", "txt", "rtf", "odt", "pptx", "xlsx"],
    "images": ["jpg", "jpeg", "png", "gif", "bmp", "svg", "webp"],
    "archives": ["zip", "tar", "gz", "rar", "7z"],
    "executables": ["exe", "msi", "bat", "sh", "app"],
    "videos": ["mp4", "avi", "mkv", "mov", "wmv"],
    "audio": ["mp3", "wav", "flac", "aac", "ogg"]
}


def get_extension(filename):
    """Safely extract and normalize file extension."""
    path = Path(filename)
    # Hidden files like .gitignore have no real extension
    if path.name.startswith('.') and path.suffix == '':
        return ""
    # Get extension, lowercase, strip the dot
    ext = path.suffix.lower()
    return ext[1:] if ext else ""


def categorize_file(filename):
    """Determine file category based on extension."""
    ext = get_extension(filename)
    # Check each category's extension list for a match
    for category, extensions in CATEGORIES.items():
        if ext in extensions:
            return category
    # If no match found, file goes to "other"
    return "other"


def organize_directory(source_dir):
    """Scan directory, categorize files, move them, track counts."""
    source = Path(source_dir)

    # Make sure the directory exists
    if not source.exists():
        print(f"Error: {source_dir} not found")
        return {}, [], []

    # Set up tally sheet with all categories at zero
    counts = {}
    for category in CATEGORIES:
        counts[category] = 0
    counts["other"] = 0
    errors = []
    warnings = []

    # Process each item in the directory
    for file_path in source.iterdir():
        # Skip subdirectories and log a warning
        if not file_path.is_file():
            warnings.append(f"Skipped directory: {file_path.name}")
            continue

        # Figure out which category this file belongs to
        category = categorize_file(file_path.name)

        # Create the category folder if it doesn't exist
        category_dir = source / category
        category_dir.mkdir(exist_ok=True)

        # Move the file and update the tally
        destination = category_dir / file_path.name
        try:
            shutil.move(str(file_path), str(destination))
            counts[category] += 1
            print(f"Moved: {file_path.name} → {category}/")
        except Exception as e:
            errors.append(f"{e}: {file_path.name}")
            print(f"Error moving {file_path.name}: {e}")

    return counts, errors, warnings


def generate_json_report(stats, errors, warnings, source_dir):
    """Generate JSON report with timestamp and statistics."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "source_directory": source_dir,
        "total_files": sum(stats.values()),
        "categories": stats,
        "organized_files": sum(stats.values()),
        "errors": errors,
        "warnings": warnings
    }

    report_path = Path(source_dir) / "organization_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    return report


def generate_text_report(stats, errors, warnings, source_dir):
    """Generate human-readable text report."""
    total = sum(stats.values())

    report = "=" * 80 + "\n"
    report += "FILE ORGANIZATION REPORT\n"
    report += "=" * 80 + "\n"
    report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += f"Source Directory: {source_dir}\n\n"

    report += "SUMMARY\n"
    report += "-" * 8 + "\n"
    report += f"Total Files Found: {total}\n"
    report += f"Successfully Organized: {total - len(errors)}\n"
    report += f"Errors: {len(errors)}\n\n"

    report += "CATEGORY BREAKDOWN\n"
    report += "-" * 18 + "\n"
    for category, count in stats.items():
        percentage = (count / total * 100) if total > 0 else 0
        report += f"{category.upper():15} {count:4} files ({percentage:.1f}%)\n"

    if errors or warnings:
        report += "\nERRORS & WARNINGS\n"
        report += "-" * 17 + "\n"
        for error in errors:
            report += f"❌ {error}\n"
        for warning in warnings:
            report += f"⚠️  {warning}\n"

    report += "\n" + "=" * 80 + "\n"
    report += "Organization complete!\n"
    report += "=" * 80 + "\n"

    report_path = Path(source_dir) / "organization_report.txt"
    with open(report_path, "w") as f:
        f.write(report)

    return report


def main():
    """Main function to run the organizer."""
    source_dir = sys.argv[1] if len(sys.argv) > 1 else "downloads"
    print(f"Organizing files in: {source_dir}")

    result = organize_directory(source_dir)

    if result:
        counts, errors, warnings = result
        generate_json_report(counts, errors, warnings, source_dir)
        generate_text_report(counts, errors, warnings, source_dir)
        print("\nReports generated successfully!")
    else:
        print("No files were organized.")


if __name__ == "__main__":
    main()
