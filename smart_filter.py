"""
Smart Filter Module
===================

Filters and ranks files by complexity to identify the riskiest code.
Focuses on logic files (source code) and excludes static assets.
"""

from pathlib import Path
from typing import Any


# File extensions to INCLUDE (source code / logic files)
LOGIC_EXTENSIONS: set[str] = {
    # Python
    '.py', '.pyw', '.pyx', '.pxd',
    # JavaScript/TypeScript
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    # Go
    '.go',
    # Java/Kotlin
    '.java', '.kt', '.kts',
    # C/C++
    '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hxx',
    # C#
    '.cs',
    # Rust
    '.rs',
    # Ruby
    '.rb', '.rake',
    # PHP
    '.php',
    # Swift
    '.swift',
    # Scala
    '.scala',
    # Shell
    '.sh', '.bash', '.zsh', '.fish',
    # PowerShell
    '.ps1', '.psm1',
    # SQL
    '.sql',
    # Lua
    '.lua',
    # Perl
    '.pl', '.pm',
    # R
    '.r', '.R',
    # Dart
    '.dart',
    # Elixir/Erlang
    '.ex', '.exs', '.erl',
    # Haskell
    '.hs',
    # Clojure
    '.clj', '.cljs',
    # F#
    '.fs', '.fsx',
}

# File extensions to EXCLUDE (static assets, configs, data)
EXCLUDED_EXTENSIONS: set[str] = {
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',
    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    # Data/Config (non-logic)
    '.json', '.yaml', '.yml', '.xml', '.toml', '.ini', '.cfg',
    # Markup/Styling
    '.html', '.htm', '.css', '.scss', '.sass', '.less',
    # Documentation
    '.md', '.rst', '.txt', '.doc', '.docx', '.pdf',
    # Binary/Compiled
    '.exe', '.dll', '.so', '.dylib', '.o', '.a', '.lib',
    '.pyc', '.pyo', '.class', '.jar', '.war',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z',
    # Media
    '.mp3', '.mp4', '.wav', '.avi', '.mov',
    # Lock files
    '.lock',
    # Other
    '.map', '.min.js', '.min.css',
}

# Directories to exclude
# NOTE: 'packages' and 'vendor' are INTENTIONALLY NOT EXCLUDED.
# Laravel/PHP apps (like Krayin CRM) store source code in packages/.
# Only exclude true dependency folders like node_modules.
EXCLUDED_DIRS: set[str] = {
    'node_modules', 'venv', '.venv', 'env', '.env',
    '__pycache__', '.git', '.svn', '.hg',
    '.idea', '.vscode',
    'dist', 'build', 'target', 'out', 'bin',
    'coverage', '.coverage', 'htmlcov',
    '.pytest_cache', '.mypy_cache', '.tox',
}


def _is_logic_file(file_path: str) -> bool:
    """
    Check if a file is a logic/source code file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file should be included in analysis
    """
    path = Path(file_path)
    ext = path.suffix.lower()
    
    # Check extension
    if ext in EXCLUDED_EXTENSIONS:
        return False
    
    if ext in LOGIC_EXTENSIONS:
        # Also check if in excluded directory
        parts = path.parts
        if any(excluded in parts for excluded in EXCLUDED_DIRS):
            return False
        return True
    
    return False


def _extract_files_from_scc(scc_results: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract individual file information from SCC results.
    
    SCC output structure varies - it may have files nested under languages.
    This function normalizes the output to a flat list of files.
    
    Args:
        scc_results: Raw SCC output dictionary
        
    Returns:
        List of file dictionaries with Name, Complexity, Lines, etc.
    """
    files: list[dict[str, Any]] = []
    
    # SCC returns results grouped by language
    if isinstance(scc_results, list):
        # Direct list of language groups
        languages = scc_results
    elif isinstance(scc_results, dict):
        # May be wrapped in a dict
        languages = scc_results.get('languages', scc_results.get('Languages', []))
        if not languages and 'files' in scc_results:
            # Or may have direct files list
            return scc_results['files']
    else:
        return []
    
    # Extract files from each language group
    for lang_group in languages:
        if isinstance(lang_group, dict):
            lang_files = lang_group.get('Files', lang_group.get('files', []))
            if lang_files:
                for f in lang_files:
                    # Normalize field names
                    # SCC uses lowercase keys: 'complexity', 'lines', 'code', etc.
                    # Handle both cases for compatibility
                    complexity = f.get('Complexity', f.get('complexity', 0))
                    lines = f.get('Lines', f.get('lines', 0))
                    code = f.get('Code', f.get('code', 0))
                    comments = f.get('Comments', f.get('comments', 0))
                    blanks = f.get('Blanks', f.get('Blank', f.get('blanks', f.get('blank', 0))))
                    location = f.get('Location', f.get('location', f.get('Name', f.get('name', f.get('Filename', f.get('filename', ''))))))
                    
                    files.append({
                        'Name': location,
                        'Complexity': complexity,
                        'Lines': lines,
                        'Code': code,
                        'Comments': comments,
                        'Blanks': blanks,
                        'Language': lang_group.get('Name', lang_group.get('name', 'Unknown')),
                        'Bytes': f.get('Bytes', f.get('bytes', 0)),
                    })
    
    return files


def filter_risky_files(
    scc_results: dict[str, Any] | list[Any],
    top_n: int = 50,
    top_percent: float = 0.05,
    return_metadata: bool = False
) -> list[dict[str, Any]] | tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Filter and rank files by complexity to identify the riskiest code.
    
    Logic:
    1. Extract all files from SCC results
    2. Filter to only include logic/source code files
    3. Sort by Complexity (descending)
    4. Return Top N files, or Top X% if total count < N
    
    Args:
        scc_results: Raw SCC output (dict or list)
        top_n: Maximum number of files to return (default: 50)
        top_percent: Percentage of files to return if count < top_n (default: 5%)
        return_metadata: If True, returns (files, metadata) tuple with total counts
        
    Returns:
        List of file dictionaries sorted by complexity (highest first)
        If return_metadata=True: (files, {'total_scc_files': N, 'total_logic_files': N})
    """
    # Extract files from SCC structure
    all_files = _extract_files_from_scc(scc_results)
    total_scc_files = len(all_files)
    
    if not all_files:
        print("[!] No files found in SCC results")
        if return_metadata:
            return [], {'total_scc_files': 0, 'total_logic_files': 0, 'total_lines': 0}
        return []
    
    print(f"[*] Total files from SCC: {total_scc_files}")
    
    # Filter to logic files only
    logic_files = [f for f in all_files if _is_logic_file(f.get('Name', ''))]
    total_logic_files = len(logic_files)
    total_lines = sum(f.get('Lines', 0) for f in logic_files)
    
    print(f"[*] Logic files after filtering: {total_logic_files}")
    
    if not logic_files:
        print("[!] No logic files found after filtering")
        if return_metadata:
            return [], {'total_scc_files': total_scc_files, 'total_logic_files': 0, 'total_lines': 0}
        return []
    
    # Sort by complexity (descending)
    sorted_files = sorted(
        logic_files,
        key=lambda f: f.get('Complexity', 0),
        reverse=True
    )
    
    # Determine how many files to return
    total_count = len(sorted_files)
    
    if total_count >= top_n:
        result_count = top_n
    else:
        # Use percentage-based cutoff for smaller codebases
        result_count = max(1, int(total_count * top_percent))
    
    risky_files = sorted_files[:result_count]
    
    print(f"[*] Selected top {len(risky_files)} risky files")
    
    # Add rank to each file
    for i, f in enumerate(risky_files, 1):
        f['Rank'] = i
    
    if return_metadata:
        metadata = {
            'total_scc_files': total_scc_files,
            'total_logic_files': total_logic_files,
            'total_lines': total_lines,
        }
        return risky_files, metadata
    
    return risky_files


def get_complexity_summary(risky_files: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Generate summary statistics from filtered risky files.
    
    Args:
        risky_files: List of files from filter_risky_files()
        
    Returns:
        Dictionary with summary statistics
    """
    if not risky_files:
        return {
            'total_files': 0,
            'total_complexity': 0,
            'avg_complexity': 0.0,
            'max_complexity': 0,
            'total_lines': 0,
            'total_code_lines': 0,
        }
    
    complexities = [f.get('Complexity', 0) for f in risky_files]
    
    return {
        'total_files': len(risky_files),
        'total_complexity': sum(complexities),
        'avg_complexity': sum(complexities) / len(risky_files),
        'max_complexity': max(complexities),
        'total_lines': sum(f.get('Lines', 0) for f in risky_files),
        'total_code_lines': sum(f.get('Code', 0) for f in risky_files),
        'languages': list(set(f.get('Language', 'Unknown') for f in risky_files)),
    }


if __name__ == "__main__":
    # Quick test with sample data
    sample_scc = [
        {
            "Name": "Python",
            "Files": [
                {"Location": "src/main.py", "Complexity": 45, "Lines": 200, "Code": 150},
                {"Location": "src/utils.py", "Complexity": 12, "Lines": 80, "Code": 60},
                {"Location": "tests/test_main.py", "Complexity": 5, "Lines": 50, "Code": 40},
                {"Location": "static/styles.css", "Complexity": 0, "Lines": 100, "Code": 100},
            ]
        },
        {
            "Name": "JavaScript", 
            "Files": [
                {"Location": "frontend/app.js", "Complexity": 78, "Lines": 400, "Code": 320},
                {"Location": "frontend/utils.js", "Complexity": 23, "Lines": 150, "Code": 120},
            ]
        }
    ]
    
    risky = filter_risky_files(sample_scc, top_n=10)
    print("\nRisky files:")
    for f in risky:
        print(f"  {f['Rank']}. {f['Name']} - Complexity: {f['Complexity']}")
    
    summary = get_complexity_summary(risky)
    print(f"\nSummary: {summary}")
