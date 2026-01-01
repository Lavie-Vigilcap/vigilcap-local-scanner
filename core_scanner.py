"""
Core Scanner Module
===================

Runs external binaries (scc, gitleaks) and returns parsed results.
Handles both development and compiled (Nuitka/PyInstaller) execution contexts.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional


def get_resource_path(filename: str) -> Path:
    """
    Get the absolute path to a resource file (binary).
    
    Handles both development mode and compiled executable mode:
    - In compiled mode: Uses sys._MEIPASS (PyInstaller) or __compiled__ (Nuitka)
    - In development mode: Uses relative path from project root
    
    Args:
        filename: Name of the file in the 'bin' directory (e.g., 'scc.exe')
        
    Returns:
        Path object to the resource file
        
    Raises:
        FileNotFoundError: If the binary cannot be found in any expected location
    """
    # Check for Nuitka compiled mode
    if "__compiled__" in dir():
        # Nuitka stores data files relative to the executable
        base_path = Path(sys.executable).parent
    # Check for PyInstaller compiled mode
    elif hasattr(sys, '_MEIPASS'):
        base_path = Path(sys._MEIPASS)
    else:
        # Development mode - look relative to this file's location
        base_path = Path(__file__).parent.parent
    
    resource_path = base_path / "bin" / filename
    
    if not resource_path.exists():
        # Fallback: check if binary is in PATH
        import shutil
        path_binary = shutil.which(filename.replace('.exe', ''))
        if path_binary:
            return Path(path_binary)
        
        raise FileNotFoundError(
            f"Binary '{filename}' not found at '{resource_path}' or in system PATH. "
            f"Please ensure the binary exists in the 'bin' directory."
        )
    
    return resource_path


def run_scc(target_path: str) -> dict[str, Any]:
    """
    Run SCC (Sloc, Cloc and Code) complexity analyzer.
    
    Args:
        target_path: Path to the directory to scan
        
    Returns:
        Dictionary containing SCC output with file-level complexity metrics
        Always returns a dict with 'languages' key (list) and 'error' key (str or None)
        
    Raises:
        FileNotFoundError: If scc.exe is not found
    """
    scc_path = get_resource_path("scc.exe")
    
    try:
        # CRITICAL: Use --by-file to get file-level details with Complexity per file
        result = subprocess.run(
            [str(scc_path), "-f", "json", "--by-file", target_path],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )
        
        # Debug: Print raw output if there's an issue
        if result.returncode != 0:
            print(f"[DEBUG] SCC exit code: {result.returncode}")
            print(f"[DEBUG] SCC stderr: {result.stderr[:500] if result.stderr else 'None'}")
        
        if not result.stdout.strip():
            print("[DEBUG] SCC returned empty output")
            return {"languages": [], "error": "SCC returned empty output"}
        
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"[DEBUG] SCC raw output (first 500 chars): {result.stdout[:500]}")
            return {"languages": [], "error": f"Failed to parse SCC JSON: {e}"}
        
        # SCC returns a list of language objects directly
        # Wrap in consistent dict format
        if isinstance(parsed, list):
            # Debug: Show structure
            if parsed:
                first_lang = parsed[0]
                has_files = 'Files' in first_lang
                print(f"[DEBUG] SCC returned {len(parsed)} language groups, has Files: {has_files}")
            return {"languages": parsed, "error": None}
        elif isinstance(parsed, dict):
            # Already a dict (shouldn't happen with scc, but handle it)
            if "languages" not in parsed:
                parsed["languages"] = []
            parsed["error"] = None
            return parsed
        else:
            return {"languages": [], "error": f"Unexpected SCC output type: {type(parsed)}"}
    
    except subprocess.TimeoutExpired:
        return {"languages": [], "error": "SCC scan timed out after 5 minutes"}
    except Exception as e:
        print(f"[DEBUG] SCC exception: {e}")
        return {"languages": [], "error": f"SCC execution failed: {e}"}


def run_gitleaks(target_path: str) -> dict[str, Any]:
    """
    Run Gitleaks security scanner to detect secrets and credentials.
    
    Args:
        target_path: Path to the directory to scan
        
    Returns:
        Dictionary containing detected leaks and metadata
        
    Raises:
        FileNotFoundError: If gitleaks.exe is not found
    """
    gitleaks_path = get_resource_path("gitleaks.exe")
    
    # Create a temporary file for the report
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
        report_path = temp_file.name
    
    try:
        # Run gitleaks - note: exit code 1 means leaks found (not an error)
        result = subprocess.run(
            [
                str(gitleaks_path), 
                "detect",
                "--source", target_path,
                "--report-path", report_path,
                "--report-format", "json",
                "--no-git"  # Scan all files, not just git tracked
            ],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Read the report file
        if os.path.exists(report_path):
            with open(report_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    leaks = json.loads(content)
                else:
                    leaks = []
        else:
            leaks = []
        
        return {
            "leaks": leaks,
            "leak_count": len(leaks),
            "critical_count": sum(1 for leak in leaks if _is_critical_leak(leak)),
            "error": None
        }
    
    except subprocess.TimeoutExpired:
        return {"leaks": [], "leak_count": 0, "critical_count": 0, "error": "Gitleaks scan timed out"}
    except json.JSONDecodeError as e:
        return {"leaks": [], "leak_count": 0, "critical_count": 0, "error": f"Failed to parse Gitleaks output: {e}"}
    except Exception as e:
        return {"leaks": [], "leak_count": 0, "critical_count": 0, "error": f"Gitleaks execution failed: {e}"}
    finally:
        # Clean up temporary file
        if os.path.exists(report_path):
            try:
                os.unlink(report_path)
            except OSError:
                pass


def _is_critical_leak(leak: dict[str, Any]) -> bool:
    """
    Determine if a leak is critical based on its type.
    
    Critical leaks include: API keys, private keys, passwords, tokens.
    """
    critical_keywords = [
        'private', 'secret', 'password', 'api_key', 'apikey', 
        'token', 'credential', 'auth', 'jwt', 'bearer'
    ]
    
    rule_id = leak.get('RuleID', '').lower()
    description = leak.get('Description', '').lower()
    
    return any(keyword in rule_id or keyword in description for keyword in critical_keywords)


def run_scan(target_path: str) -> dict[str, Any]:
    """
    Run complete security and complexity scan on target directory.
    
    This is the main entry point that orchestrates both SCC and Gitleaks scans.
    
    Args:
        target_path: Path to the directory to scan
        
    Returns:
        Dictionary containing:
            - scc_results: Complexity analysis results
            - gitleaks_results: Security scan results
            - scan_path: The scanned directory path
            - errors: List of any errors encountered
    """
    target = Path(target_path)
    
    if not target.exists():
        return {
            "scc_results": {"languages": [], "files": []},
            "gitleaks_results": {"leaks": [], "leak_count": 0, "critical_count": 0},
            "scan_path": str(target_path),
            "errors": [f"Target path does not exist: {target_path}"]
        }
    
    if not target.is_dir():
        return {
            "scc_results": {"languages": [], "files": []},
            "gitleaks_results": {"leaks": [], "leak_count": 0, "critical_count": 0},
            "scan_path": str(target_path),
            "errors": [f"Target path is not a directory: {target_path}"]
        }
    
    errors: list[str] = []
    
    # Run SCC complexity scan
    try:
        print("[*] Running SCC complexity analysis...")
        scc_results = run_scc(str(target))
        if scc_results.get("error"):
            errors.append(f"SCC: {scc_results['error']}")
    except FileNotFoundError as e:
        scc_results = {"languages": [], "files": []}
        errors.append(f"SCC binary not found: {e}")
    
    # Run Gitleaks security scan
    try:
        print("[*] Running Gitleaks security scan...")
        gitleaks_results = run_gitleaks(str(target))
        if gitleaks_results.get("error"):
            errors.append(f"Gitleaks: {gitleaks_results['error']}")
    except FileNotFoundError as e:
        gitleaks_results = {"leaks": [], "leak_count": 0, "critical_count": 0}
        errors.append(f"Gitleaks binary not found: {e}")
    
    return {
        "scc_results": scc_results,
        "gitleaks_results": gitleaks_results,
        "scan_path": str(target),
        "errors": errors
    }


if __name__ == "__main__":
    # Quick test
    import pprint
    test_path = os.path.dirname(os.path.dirname(__file__))
    results = run_scan(test_path)
    pprint.pprint(results)
