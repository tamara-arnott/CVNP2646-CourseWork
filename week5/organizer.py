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
    "documents": ["pdf", "doc", "docx", "txt", "rtf", "odt"],
    "images": ["jpg", "jpeg", "png", "gif", "bmp", "svg"],
    "archives": ["zip", "tar", "gz", "rar", "7z"],
    "executables": ["exe", "msi", "bat", "sh"],
    "videos": ["mp4", "avi", "mkv", "mov"],
    "audio": ["mp3", "wav", "flac", "aac"]
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
        return {}

    # Set up tally sheet with all categories at zero
    counts = {}
    for category in CATEGORIES:
        counts[category] = 0
    counts["other"] = 0

    # Process each file in the directory
    for file_path in source.iterdir():
        # Skip subdirectories, only process files
        if not file_path.is_file():
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
            print(f"Error moving {file_path.name}: {e}")

    return counts
def generate_json_report(stats, source_dir):
    """Generate JSON report with timestamp and statistics."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "source_directory": source_dir,
        "total_files": sum(stats.values()),
        "categories": stats
    }

    report_path = Path(source_dir) / "organization_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    return report
def generate_text_report(stats, source_dir):
    """Generate human-readable text report."""
    total = sum(stats.values())

    report = "FILE ORGANIZATION REPORT\n"
    report += "=" * 40 + "\n\n"
    report += f"Source: {source_dir}\n"
    report += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += f"Total Files: {total}\n\n"

    for category, count in stats.items():
        percentage = (count / total * 100) if total > 0 else 0
        report += f"  {category.upper():15} {count:4} ({percentage:.1f}%)\n"

    report_path = Path(source_dir) / "organization_report.txt"
    with open(report_path, "w") as f:
        f.write(report)

    return report
def main():
    """Main function to run the organizer."""
    source_dir = sys.argv[1] if len(sys.argv) > 1 else "downloads"
    print(f"Organizing files in: {source_dir}")

    counts = organize_directory(source_dir)

    if counts:
        generate_json_report(counts, source_dir)
        generate_text_report(counts, source_dir)
        print("\nReports generated successfully!")
    else:
        print("No files were organized.")


if __name__ == "__main__":
    main()
    
