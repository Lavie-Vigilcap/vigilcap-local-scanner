"""
Dependency Scanner Module
=========================

Scans project directories for dependency manifest files and extracts
package information for risk analysis.

Sprint 7: Added TOXIC_LICENSES lookup for offline legal audit.

Supports:
- npm (package.json)
- Python (requirements.txt, Pipfile, pyproject.toml)
- Go (go.mod)
- Java (pom.xml)
"""

import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


# ============================================================
# TOXIC LICENSES (Sprint 7 - Offline Legal Audit)
# ============================================================
# These licenses create "viral" contamination risk for M&A deals.
# If ANY dependency uses these, flag as CRITICAL RISK.
TOXIC_LICENSES = [
    'GPL',       # GNU General Public License (any version)
    'GPL-2.0',
    'GPL-3.0',
    'GPLv2',
    'GPLv3',
    'AGPL',      # Affero GPL - even more restrictive
    'AGPL-3.0',
    'SSPL',      # Server Side Public License (MongoDB)
    'CC-BY-NC',  # Creative Commons Non-Commercial
    'CC-BY-NC-SA',
    'LGPL',      # Lesser GPL - still risky for statically linked code
    'LGPL-2.1',
    'LGPL-3.0',
    'OSL',       # Open Software License
    'CPAL',      # Common Public Attribution License
    'EUPL',      # European Union Public License
]

# Known toxic packages (hardcoded for common risky dependencies)
KNOWN_TOXIC_PACKAGES = {
    'mysql': 'GPL',
    'readline': 'GPL',
    'ghostscript': 'AGPL',
    'mongodb-community': 'SSPL',
    'itext': 'AGPL',
    'qt': 'GPL/LGPL',
    'ffmpeg': 'GPL',
    'x264': 'GPL',
}


def scan_dependencies(root_path: str) -> list[dict[str, Any]]:
    """
    Scan a directory for dependency manifest files and extract packages.
    
    Args:
        root_path: Root directory to scan
        
    Returns:
        List of dependency dicts with 'name', 'version', 'type', 'source_file'
    """
    root = Path(root_path)
    dependencies = []
    
    # Find and parse all manifest files
    for manifest_path in root.rglob("*"):
        if manifest_path.is_file():
            filename = manifest_path.name.lower()
            
            try:
                if filename == "package.json":
                    deps = _parse_package_json(manifest_path)
                    dependencies.extend(deps)
                elif filename == "composer.json":
                    deps = _parse_composer_json(manifest_path)
                    dependencies.extend(deps)
                elif filename == "requirements.txt":
                    deps = _parse_requirements_txt(manifest_path)
                    dependencies.extend(deps)
                elif filename == "pipfile":
                    deps = _parse_pipfile(manifest_path)
                    dependencies.extend(deps)
                elif filename == "pyproject.toml":
                    deps = _parse_pyproject_toml(manifest_path)
                    dependencies.extend(deps)
                elif filename == "go.mod":
                    deps = _parse_go_mod(manifest_path)
                    dependencies.extend(deps)
                elif filename == "pom.xml":
                    deps = _parse_pom_xml(manifest_path)
                    dependencies.extend(deps)
                elif filename == "build.gradle" or filename == "build.gradle.kts":
                    deps = _parse_gradle(manifest_path)
                    dependencies.extend(deps)
                elif filename == "gemfile":
                    deps = _parse_gemfile(manifest_path)
                    dependencies.extend(deps)
            except Exception as e:
                print(f"[!] Error parsing {manifest_path}: {e}")
                continue
    
    # Deduplicate by name + type
    seen = set()
    unique_deps = []
    for dep in dependencies:
        key = (dep['name'].lower(), dep['type'])
        if key not in seen:
            seen.add(key)
            unique_deps.append(dep)
    
    return unique_deps


def _parse_package_json(path: Path) -> list[dict[str, Any]]:
    """Parse npm package.json."""
    deps = []
    relative_path = str(path.name)
    
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Regular dependencies
    for name, version in data.get('dependencies', {}).items():
        deps.append({
            'name': name,
            'version': _clean_version(version),
            'type': 'npm',
            'source_file': relative_path,
            'dev': False
        })
    
    # Dev dependencies
    for name, version in data.get('devDependencies', {}).items():
        deps.append({
            'name': name,
            'version': _clean_version(version),
            'type': 'npm',
            'source_file': relative_path,
            'dev': True
        })
    
    return deps


def _parse_requirements_txt(path: Path) -> list[dict[str, Any]]:
    """Parse Python requirements.txt."""
    deps = []
    relative_path = str(path.name)
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Parse package==version or package>=version etc.
            match = re.match(r'^([a-zA-Z0-9_-]+)([<>=!~]+)?(.+)?', line)
            if match:
                name = match.group(1)
                version = match.group(3) or 'latest'
                deps.append({
                    'name': name,
                    'version': version.strip(),
                    'type': 'pip',
                    'source_file': relative_path,
                    'dev': False
                })
    
    return deps


def _parse_pipfile(path: Path) -> list[dict[str, Any]]:
    """Parse Python Pipfile (simple parsing)."""
    deps = []
    relative_path = str(path.name)
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Simple regex to find package = "version" patterns
    in_packages = False
    in_dev = False
    
    for line in content.split('\n'):
        if '[packages]' in line:
            in_packages = True
            in_dev = False
        elif '[dev-packages]' in line:
            in_packages = True
            in_dev = True
        elif line.startswith('['):
            in_packages = False
        elif in_packages and '=' in line:
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*["\']?([^"\']+)?', line)
            if match:
                deps.append({
                    'name': match.group(1),
                    'version': match.group(2) or 'latest',
                    'type': 'pip',
                    'source_file': relative_path,
                    'dev': in_dev
                })
    
    return deps


def _parse_pyproject_toml(path: Path) -> list[dict[str, Any]]:
    """Parse Python pyproject.toml (simple parsing)."""
    deps = []
    relative_path = str(path.name)
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Look for dependencies array
    dep_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
    if dep_match:
        dep_str = dep_match.group(1)
        # Parse quoted strings
        for match in re.finditer(r'"([^"]+)"', dep_str):
            dep_line = match.group(1)
            # Parse name and version
            name_match = re.match(r'^([a-zA-Z0-9_-]+)', dep_line)
            if name_match:
                version_match = re.search(r'[<>=]+(.+)', dep_line)
                deps.append({
                    'name': name_match.group(1),
                    'version': version_match.group(1) if version_match else 'latest',
                    'type': 'pip',
                    'source_file': relative_path,
                    'dev': False
                })
    
    return deps


def _parse_go_mod(path: Path) -> list[dict[str, Any]]:
    """Parse Go go.mod file."""
    deps = []
    relative_path = str(path.name)
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find require block
    require_match = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
    if require_match:
        for line in require_match.group(1).strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2:
                deps.append({
                    'name': parts[0],
                    'version': parts[1],
                    'type': 'go',
                    'source_file': relative_path,
                    'dev': False
                })
    
    # Single line requires
    for match in re.finditer(r'require\s+(\S+)\s+(\S+)', content):
        deps.append({
            'name': match.group(1),
            'version': match.group(2),
            'type': 'go',
            'source_file': relative_path,
            'dev': False
        })
    
    return deps


def _parse_pom_xml(path: Path) -> list[dict[str, Any]]:
    """Parse Java Maven pom.xml."""
    deps = []
    relative_path = str(path.name)
    
    try:
        tree = ElementTree.parse(path)
        root = tree.getroot()
        
        # Handle namespace
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        
        # Find dependencies
        for dep in root.findall('.//m:dependency', ns) + root.findall('.//dependency'):
            group_id = dep.find('m:groupId', ns) or dep.find('groupId')
            artifact_id = dep.find('m:artifactId', ns) or dep.find('artifactId')
            version = dep.find('m:version', ns) or dep.find('version')
            scope = dep.find('m:scope', ns) or dep.find('scope')
            
            if artifact_id is not None:
                name = artifact_id.text
                if group_id is not None:
                    name = f"{group_id.text}:{artifact_id.text}"
                
                deps.append({
                    'name': name,
                    'version': version.text if version is not None else 'latest',
                    'type': 'maven',
                    'source_file': relative_path,
                    'dev': scope is not None and scope.text == 'test'
                })
    except Exception:
        pass
    
    return deps


def _parse_gemfile(path: Path) -> list[dict[str, Any]]:
    """Parse Ruby Gemfile."""
    deps = []
    relative_path = str(path.name)
    
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Match gem 'name', 'version' or gem "name", "version"
            match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
            if match:
                deps.append({
                    'name': match.group(1),
                    'version': match.group(2) or 'latest',
                    'type': 'gem',
                    'source_file': relative_path,
                    'dev': ':development' in line or ':test' in line
                })
    
    return deps


def _parse_composer_json(path: Path) -> list[dict[str, Any]]:
    """Parse PHP composer.json."""
    deps = []
    relative_path = str(path.name)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Regular dependencies
        for name, version in data.get('require', {}).items():
            # Skip PHP version constraints
            if name.lower() in ['php', 'ext-json', 'ext-mbstring', 'ext-openssl', 'ext-pdo', 'ext-curl']:
                continue
            deps.append({
                'name': name,
                'version': _clean_version(version),
                'type': 'composer',
                'source_file': relative_path,
                'dev': False
            })
        
        # Dev dependencies
        for name, version in data.get('require-dev', {}).items():
            deps.append({
                'name': name,
                'version': _clean_version(version),
                'type': 'composer',
                'source_file': relative_path,
                'dev': True
            })
    except Exception:
        pass
    
    return deps


def _parse_gradle(path: Path) -> list[dict[str, Any]]:
    """Parse Java Gradle build.gradle or build.gradle.kts."""
    deps = []
    relative_path = str(path.name)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Match implementation 'group:artifact:version' or implementation("group:artifact:version")
        patterns = [
            r"implementation\s*[\('\"]([^'\"]+)[\'\"\)]",
            r"api\s*[\('\"]([^'\"]+)[\'\"\)]",
            r"compile\s*[\('\"]([^'\"]+)[\'\"\)]",
            r"testImplementation\s*[\('\"]([^'\"]+)[\'\"\)]",
            r"testCompile\s*[\('\"]([^'\"]+)[\'\"\)]",
        ]
        
        for pattern in patterns:
            is_dev = 'test' in pattern.lower()
            for match in re.finditer(pattern, content, re.IGNORECASE):
                dep_str = match.group(1)
                parts = dep_str.split(':')
                if len(parts) >= 2:
                    name = ':'.join(parts[:2]) if len(parts) > 2 else parts[0]
                    version = parts[-1] if len(parts) >= 3 else 'latest'
                    deps.append({
                        'name': name,
                        'version': version,
                        'type': 'gradle',
                        'source_file': relative_path,
                        'dev': is_dev
                    })
    except Exception:
        pass
    
    return deps


def _clean_version(version: str) -> str:
    """Clean version string (remove ^, ~, etc.)."""
    if not version:
        return 'latest'
    return version.lstrip('^~<>=!')


def check_toxic_license(dep_name: str, license_str: str = None) -> dict[str, Any]:
    """
    Check if a dependency has a toxic license (Sprint 7 - Offline Legal Audit).
    
    Args:
        dep_name: Name of the dependency
        license_str: License string if known (optional)
        
    Returns:
        Dict with 'is_toxic', 'license', 'risk_level'
    """
    dep_lower = dep_name.lower()
    
    # Check against known toxic packages first
    if dep_lower in KNOWN_TOXIC_PACKAGES:
        return {
            'is_toxic': True,
            'license': KNOWN_TOXIC_PACKAGES[dep_lower],
            'risk_level': 'CRITICAL',
            'reason': f'Known viral license: {KNOWN_TOXIC_PACKAGES[dep_lower]}'
        }
    
    # Check license string if provided
    if license_str:
        license_upper = license_str.upper()
        for toxic in TOXIC_LICENSES:
            if toxic.upper() in license_upper:
                return {
                    'is_toxic': True,
                    'license': license_str,
                    'risk_level': 'CRITICAL',
                    'reason': f'Toxic license detected: {license_str}'
                }
    
    return {
        'is_toxic': False,
        'license': license_str or 'Unknown',
        'risk_level': 'OK',
        'reason': None
    }


def analyze_dependencies_for_risk(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze all dependencies for license risks (Sprint 7 - Offline).
    
    Returns comprehensive risk analysis including toxic licenses.
    """
    toxic_deps = []
    safe_deps = []
    
    for dep in dependencies:
        check = check_toxic_license(dep['name'], dep.get('license'))
        dep['license_risk'] = check
        
        if check['is_toxic']:
            toxic_deps.append({
                'name': dep['name'],
                'version': dep.get('version', 'unknown'),
                'license': check['license'],
                'reason': check['reason']
            })
        else:
            safe_deps.append(dep['name'])
    
    return {
        'total_dependencies': len(dependencies),
        'toxic_count': len(toxic_deps),
        'toxic_dependencies': toxic_deps,
        'has_critical_license_risk': len(toxic_deps) > 0,
        'safe_count': len(safe_deps)
    }


def get_dependency_summary(dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Get summary statistics for dependencies including license risk analysis.
    
    Sprint 7: Now includes toxic license detection.
    """
    by_type = {}
    dev_count = 0
    prod_count = 0
    
    for dep in dependencies:
        dep_type = dep['type']
        by_type[dep_type] = by_type.get(dep_type, 0) + 1
        
        if dep.get('dev'):
            dev_count += 1
        else:
            prod_count += 1
    
    # Run license risk analysis
    risk_analysis = analyze_dependencies_for_risk(dependencies)
    
    return {
        'total': len(dependencies),
        'production': prod_count,
        'development': dev_count,
        'by_type': by_type,
        # Sprint 7 additions
        'toxic_count': risk_analysis['toxic_count'],
        'toxic_dependencies': risk_analysis['toxic_dependencies'],
        'has_critical_license_risk': risk_analysis['has_critical_license_risk']
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        deps = scan_dependencies(sys.argv[1])
        print(f"Found {len(deps)} dependencies:")
        for dep in deps[:20]:
            print(f"  {dep['type']:8} {dep['name']:30} {dep['version']}")
        
        # Test license check
        print("\n--- License Risk Analysis ---")
        summary = get_dependency_summary(deps)
        print(f"Toxic dependencies: {summary['toxic_count']}")
        for toxic in summary['toxic_dependencies']:
            print(f"  ⚠️ {toxic['name']}: {toxic['reason']}")
    else:
        print("Usage: python dependency_scanner.py <directory>")
