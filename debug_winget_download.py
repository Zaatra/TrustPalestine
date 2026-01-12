"""Debug script to test WinGet download functionality."""
import subprocess
import os
from pathlib import Path

def test_winget_download():
    """Test if WinGet can download a package."""
    package_id = "7zip.7zip"
    print(f"Target Package: {package_id}")

    # FIX: Create a permanent directory in the current folder instead of a temp one
    current_dir = Path.cwd()
    download_dir = current_dir / "winget_test_downloads"
    
    # Create the directory if it doesn't exist
    download_dir.mkdir(exist_ok=True)
    
    print(f"Download directory: {download_dir}")

    # Build WinGet command
    cmd = [
        "winget",
        "download",
        "--id", package_id,
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--verbose",
        "-d", str(download_dir),
    ]

    print(f"Running command: {' '.join(cmd)}")
    print("-" * 80)

    try:
        # Run command
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
    except subprocess.TimeoutExpired:
        print("ERROR: WinGet command timed out.")
        return

    print(f"Return code: {result.returncode}")

    if result.returncode != 0:
        print(f"\nSTDOUT:\n{result.stdout}")
        print(f"\nSTDERR:\n{result.stderr}")
    else:
        print("\nCommand successful.")

    print("-" * 80)

    # Check files
    print("\nFiles in download directory:")
    files = list(download_dir.rglob("*"))
    
    if files:
        for file in sorted(files):
            if file.is_file():
                size_mb = file.stat().st_size / (1024 * 1024)
                print(f"  [FILE] {file.name} ({size_mb:.2f} MB)")
            else:
                print(f"  [DIR]  {file.name}")
        
        print(f"\nSUCCESS! You can find the files here:\n{download_dir}")
    else:
        print("  (no files found)")

if __name__ == "__main__":
    test_winget_download()