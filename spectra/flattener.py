import os
import shutil
from pathlib import Path


def flatten_and_batch(batch_size: int = 10, target_dir_name: str = "flattened"):
    # Root directory where this script resides
    base_dir = Path(__file__).resolve().parent
    script_file = Path(__file__).resolve()
    target_dir = base_dir / target_dir_name

    # Create base output directory if it doesn't exist
    target_dir.mkdir(exist_ok=True)

    collected_files = []

    # 1. Walk the directory tree and copy files into flattened/
    for root, dirs, files in os.walk(base_dir):
        root_path = Path(root).resolve()

        # Prevent searching inside the output directory itself
        if target_dir in root_path.parents or root_path == target_dir:
            continue

        for file in files:
            source_file = root_path / file

            # Exclude the script itself and any .gitignore files
            if source_file == script_file:
                continue
            if file == ".gitignore" or file.endswith(".gitignore"):
                continue

            # Compute relative path components from base directory
            rel_path = source_file.relative_to(base_dir)

            # If the file is directly in the base directory, keep its original name.
            # Otherwise, join all parent folder names with underscores before the file name.
            parts = rel_path.parts
            if len(parts) == 1:
                flat_filename = parts[0]
            else:
                flat_filename = "_".join(parts)

            dest_file = target_dir / flat_filename

            # Handle edge cases where name collisions might occur
            if dest_file.exists():
                stem = dest_file.stem
                suffix = dest_file.suffix
                counter = 1
                while dest_file.exists():
                    dest_file = target_dir / f"{stem}_{counter}{suffix}"
                    counter += 1

            shutil.copy2(source_file, dest_file)
            collected_files.append(dest_file)

    print(f"Copied {len(collected_files)} files to '{target_dir_name}/'.")

    # 2. Partition collected files into batches of 10
    batch_count = 0
    for i in range(0, len(collected_files), batch_size):
        batch_folder = target_dir / f"batch_{batch_count}"
        batch_folder.mkdir(exist_ok=True)

        batch = collected_files[i : i + batch_size]
        for file_path in batch:
            shutil.move(str(file_path), str(batch_folder / file_path.name))

        batch_count += 1

    print(
        f"Organized into {batch_count} batch folder(s) of up to {batch_size} files each."
    )


if __name__ == "__main__":
    flatten_and_batch()