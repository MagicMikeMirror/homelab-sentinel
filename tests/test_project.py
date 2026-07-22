from pathlib import Path


def test_required_project_files_exist():
    required = [
        "Dockerfile",
        "requirements.txt",
        "app/main.py",
        "docs/ZIMAOS.md",
    ]
    for item in required:
        assert Path(item).is_file(), f"Missing required file: {item}"
