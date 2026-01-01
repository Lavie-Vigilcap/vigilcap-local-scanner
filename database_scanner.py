"""
Database Scanner Module
========================

Sprint 8: Analyzes database schema files to identify architectural risks.
v3.0: Industrial Tech (ERP/MES) vulnerability detection.

Scans for:
- *.sql files
- schema.rb (Rails)
- structure.sql (Rails)

Identifies:
- "God Tables" (> 50 columns) - HIGH RISK
- "Heaps" (missing PRIMARY KEY) - CRITICAL RISK

Industrial Tech (v3.0):
- xp_cmdshell enabled - CRITICAL DEFAULT RISK  
- Stored Procedure Logic > 20% - DATABASE LOGIC COUPLING
- Legacy ERP ports (Firebird, Btrieve, JobBOSS)
"""

import re
from pathlib import Path
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================
GOD_TABLE_THRESHOLD = 50  # Tables with more than 50 columns
SCHEMA_FILE_PATTERNS = ['*.sql', 'schema.rb', 'structure.sql']
STORED_PROCEDURE_LOGIC_THRESHOLD = 0.20  # 20% logic = anti-pattern

# Legacy ERP Ports (Industrial Tech / Manufacturing Blue Ocean)
LEGACY_ERP_PORTS = {
    3050: {"name": "Firebird / Fishbowl", "risk": "Business Interruption Risk"},
    3351: {"name": "Btrieve / Global Shop", "risk": "Business Interruption Risk"},
    8897: {"name": "JobBOSS Data Collection", "risk": "Business Interruption Risk"}
}


def scan_databases(root_path: str) -> dict[str, Any]:
    """
    Scan a directory for database schema files and analyze for risks.
    
    v2.5: Expanded to detect ORM-based migrations across multiple ecosystems:
    - PHP (Laravel): database/migrations/*.php with Schema::create
    - Python (Django): */migrations/*.py
    - Python (Alembic): versions/*.py
    - Ruby (Rails): db/migrate/*.rb, db/schema.rb
    - Node (Prisma): schema.prisma
    - Node (TypeORM): *.entity.ts
    - Java (Hibernate): *.hbm.xml
    - Java (Liquibase): changelog.xml
    
    Args:
        root_path: Root directory to scan
        
    Returns:
        Dictionary with database analysis results
    """
    root = Path(root_path)
    
    # =========================================================
    # PHASE 1: Find all schema files
    # =========================================================
    schema_files = []
    orm_migrations = []
    orm_type = None
    
    # Traditional SQL files
    for pattern in ['**/*.sql', '**/schema.rb', '**/structure.sql']:
        schema_files.extend(root.glob(pattern))
    
    # === PHP Laravel Migrations ===
    laravel_migrations = list(root.glob('**/database/migrations/*.php'))
    for f in laravel_migrations:
        try:
            content = f.read_text(encoding='utf-8', errors='ignore')
            if 'Schema::create' in content or 'Schema::table' in content:
                orm_migrations.append({'file': f, 'type': 'Laravel/Eloquent', 'content': content})
        except:
            pass
    if orm_migrations:
        orm_type = 'Laravel/Eloquent'
    
    # === Python Django Migrations ===
    django_migrations = list(root.glob('**/migrations/*.py'))
    for f in django_migrations:
        if f.name == '__init__.py':
            continue
        try:
            content = f.read_text(encoding='utf-8', errors='ignore')
            if 'migrations.Migration' in content or 'CreateModel' in content or 'AddField' in content:
                orm_migrations.append({'file': f, 'type': 'Django ORM', 'content': content})
                orm_type = orm_type or 'Django ORM'
        except:
            pass
    
    # === Python Alembic (Flask) ===
    alembic_migrations = list(root.glob('**/versions/*.py'))
    for f in alembic_migrations:
        try:
            content = f.read_text(encoding='utf-8', errors='ignore')
            if 'op.create_table' in content or 'op.add_column' in content:
                orm_migrations.append({'file': f, 'type': 'Alembic/Flask', 'content': content})
                orm_type = orm_type or 'Alembic/Flask'
        except:
            pass
    
    # === Ruby Rails Migrations ===
    rails_migrations = list(root.glob('**/db/migrate/*.rb'))
    for f in rails_migrations:
        orm_migrations.append({'file': f, 'type': 'ActiveRecord/Rails', 'content': ''})
        orm_type = orm_type or 'ActiveRecord/Rails'
    
    # === Node Prisma Schema ===
    prisma_files = list(root.glob('**/schema.prisma')) + list(root.glob('**/prisma/schema.prisma'))
    for f in prisma_files:
        orm_migrations.append({'file': f, 'type': 'Prisma', 'content': ''})
        orm_type = orm_type or 'Prisma'
    
    # === Node TypeORM Entities ===
    typeorm_entities = list(root.glob('**/*.entity.ts'))
    for f in typeorm_entities:
        orm_migrations.append({'file': f, 'type': 'TypeORM', 'content': ''})
        orm_type = orm_type or 'TypeORM'
    
    # === Java Hibernate Mappings ===
    hibernate_files = list(root.glob('**/*.hbm.xml'))
    for f in hibernate_files:
        orm_migrations.append({'file': f, 'type': 'Hibernate', 'content': ''})
        orm_type = orm_type or 'Hibernate'
    
    # === Java Liquibase ===
    liquibase_files = list(root.glob('**/changelog.xml')) + list(root.glob('**/db.changelog*.xml'))
    for f in liquibase_files:
        orm_migrations.append({'file': f, 'type': 'Liquibase', 'content': ''})
        orm_type = orm_type or 'Liquibase'
    
    # Filter out common non-schema SQL files
    excluded_dirs = {'node_modules', '.git', '__pycache__'}
    schema_files = [
        f for f in schema_files 
        if not any(ex in f.parts for ex in excluded_dirs)
    ]
    
    # Analyze each file
    all_tables = []
    god_tables = []
    heap_tables = []
    
    for file_path in schema_files:
        try:
            tables = _analyze_schema_file(file_path)
            all_tables.extend(tables)
            
            for table in tables:
                if table['column_count'] > GOD_TABLE_THRESHOLD:
                    god_tables.append(table)
                if not table['has_primary_key']:
                    heap_tables.append(table)
                    
        except Exception as e:
            print(f"[!] Error analyzing {file_path}: {e}")
    
    # Build risk summary
    risks = []
    
    for table in god_tables:
        risks.append({
            'type': 'GOD_TABLE',
            'severity': 'HIGH',
            'table_name': table['name'],
            'file': str(table['file']),
            'column_count': table['column_count'],
            'description': f"Table '{table['name']}' has {table['column_count']} columns (threshold: {GOD_TABLE_THRESHOLD}). Consider normalization.",
            'remediation_hours': 40
        })
    
    for table in heap_tables:
        risks.append({
            'type': 'HEAP_TABLE',
            'severity': 'CRITICAL',
            'table_name': table['name'],
            'file': str(table['file']),
            'description': f"Table '{table['name']}' has no PRIMARY KEY. This creates indexing issues and potential data integrity problems.",
            'remediation_hours': 4
        })
    
    # ============================================================
    # v3.0: Industrial Tech Vulnerability Detection
    # ============================================================
    industrial_risks = []
    xp_cmdshell_found = False
    sp_logic_coupling_files = []
    legacy_ports_found = []
    
    for file_path in schema_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for xp_cmdshell
            if check_xp_cmdshell(content):
                xp_cmdshell_found = True
                industrial_risks.append({
                    'type': 'XP_CMDSHELL',
                    'severity': 'CRITICAL',
                    'file': str(file_path),
                    'description': 'xp_cmdshell is enabled. Critical Default Risk - allows OS command execution.',
                    'remediation_hours': 8
                })
            
            # Check stored procedure logic coupling
            sp_ratio = check_stored_procedure_logic(content)
            if sp_ratio > STORED_PROCEDURE_LOGIC_THRESHOLD:
                sp_logic_coupling_files.append({
                    'file': str(file_path),
                    'logic_ratio': sp_ratio
                })
                industrial_risks.append({
                    'type': 'SP_LOGIC_COUPLING',
                    'severity': 'HIGH',
                    'file': str(file_path),
                    'description': f'Stored procedure logic is {sp_ratio:.0%} of file. Database Logic Coupling anti-pattern.',
                    'remediation_hours': 16
                })
            
            # Check for legacy port references
            found_ports = scan_legacy_ports(content)
            if found_ports:
                legacy_ports_found.extend(found_ports)
                for port_info in found_ports:
                    industrial_risks.append({
                        'type': 'LEGACY_PORT',
                        'severity': 'HIGH',
                        'file': str(file_path),
                        'port': port_info['port'],
                        'description': f"Legacy port {port_info['port']} ({port_info['name']}) detected. {port_info['risk']}.",
                        'remediation_hours': 24
                    })
                    
        except Exception as e:
            print(f"[!] Error analyzing {file_path} for Industrial Tech: {e}")
    
    # Combine all risks
    all_risks = risks + industrial_risks
    
    # Calculate legacy ERP flag (for JSON output)
    legacy_erp_flag = len(legacy_ports_found) > 0 or xp_cmdshell_found
    
    return {
        'schema_files_scanned': len(schema_files),
        'total_tables_found': len(all_tables),
        'god_tables_count': len(god_tables),
        'heap_tables_count': len(heap_tables),
        'risks': all_risks,
        'tables': all_tables,
        'god_tables': god_tables,
        'heap_tables': heap_tables,
        'total_remediation_hours': sum(r['remediation_hours'] for r in all_risks),
        # v3.0: Industrial Tech fields
        'xp_cmdshell_found': xp_cmdshell_found,
        'sp_logic_coupling_files': sp_logic_coupling_files,
        'legacy_ports_found': legacy_ports_found,
        'legacy_erp_flag': legacy_erp_flag,
        'schemas': schema_files,  # For telemetry log count
        # v2.5: ORM Migration Detection
        'orm_migrations_count': len(orm_migrations),
        'orm_type': orm_type,
        'orm_migrations': [{'file': str(m['file']), 'type': m['type']} for m in orm_migrations],
    }


def _analyze_schema_file(file_path: Path) -> list[dict[str, Any]]:
    """
    Analyze a single schema file for table definitions.
    
    Supports:
    - SQL CREATE TABLE statements
    - Rails schema.rb format
    """
    tables = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    file_ext = file_path.suffix.lower()
    file_name = file_path.name.lower()
    
    if file_name == 'schema.rb':
        tables = _parse_rails_schema(content, file_path)
    else:
        tables = _parse_sql_schema(content, file_path)
    
    return tables


def _parse_sql_schema(content: str, file_path: Path) -> list[dict[str, Any]]:
    """Parse SQL CREATE TABLE statements."""
    tables = []
    
    # Match CREATE TABLE blocks
    # Pattern: CREATE TABLE [IF NOT EXISTS] table_name (...)
    create_pattern = re.compile(
        r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"\[]?(\w+)[`"\]]?\s*\((.*?)\)',
        re.IGNORECASE | re.DOTALL
    )
    
    for match in create_pattern.finditer(content):
        table_name = match.group(1)
        table_body = match.group(2)
        
        # Count columns (lines that look like column definitions)
        column_pattern = re.compile(
            r'^\s*[`"\[]?(\w+)[`"\]]?\s+(?:INT|VARCHAR|TEXT|CHAR|DECIMAL|DATE|TIME|BOOL|FLOAT|DOUBLE|BLOB|ENUM|SET|JSON|BINARY|BIGINT|SMALLINT|TINYINT|MEDIUMINT|REAL|NUMERIC|UUID|SERIAL)',
            re.IGNORECASE | re.MULTILINE
        )
        columns = column_pattern.findall(table_body)
        
        # Check for PRIMARY KEY
        has_pk = bool(re.search(r'PRIMARY\s+KEY', table_body, re.IGNORECASE))
        
        # Also check for inline PRIMARY KEY notation
        if not has_pk:
            has_pk = bool(re.search(r'\bPRIMARY\b', table_body, re.IGNORECASE))
        
        tables.append({
            'name': table_name,
            'file': file_path,
            'column_count': len(columns) if columns else _estimate_columns(table_body),
            'has_primary_key': has_pk
        })
    
    return tables


def _parse_rails_schema(content: str, file_path: Path) -> list[dict[str, Any]]:
    """Parse Rails schema.rb format."""
    tables = []
    
    # Match create_table blocks
    # Pattern: create_table "table_name" do |t| ... end
    create_pattern = re.compile(
        r'create_table\s+["\'](\w+)["\']\s*(?:,\s*[^d]*)?do\s*\|t\|(.*?)end',
        re.IGNORECASE | re.DOTALL
    )
    
    for match in create_pattern.finditer(content):
        table_name = match.group(1)
        table_body = match.group(2)
        
        # Count t.column definitions
        column_pattern = re.compile(r't\.(\w+)\s+["\'](\w+)["\']')
        columns = column_pattern.findall(table_body)
        
        # Check for primary key (Rails usually auto-adds id, but check for custom)
        has_pk = 'id: false' not in content or 'primary_key' in table_body.lower()
        # Default Rails behavior is to have id as primary key
        if 'id: false' not in table_body:
            has_pk = True
        
        tables.append({
            'name': table_name,
            'file': file_path,
            'column_count': len(columns),
            'has_primary_key': has_pk
        })
    
    return tables


def _estimate_columns(table_body: str) -> int:
    """Estimate column count from table body by counting commas at reasonable positions."""
    # Simple heuristic: count lines that seem like column definitions
    lines = [l.strip() for l in table_body.split('\n') if l.strip() and not l.strip().startswith('--')]
    # Filter out constraint lines
    column_lines = [l for l in lines if not any(kw in l.upper() for kw in ['CONSTRAINT', 'INDEX', 'KEY ', 'UNIQUE', 'FOREIGN', 'CHECK'])]
    return max(1, len(column_lines))


# ============================================================
# INDUSTRIAL TECH (ERP/MES) VULNERABILITY DETECTION (v3.0)
# ============================================================

def check_xp_cmdshell(sql_content: str) -> bool:
    """
    Check for xp_cmdshell vulnerability in SQL configurations.
    
    Scans for:
    - value_in_use = 1 for xp_cmdshell
    - sp_configure 'xp_cmdshell', 1
    - EXEC xp_cmdshell patterns
    
    Returns True if vulnerability detected.
    """
    patterns = [
        r"xp_cmdshell.*1",  # xp_cmdshell enabled
        r"sp_configure\s+['\"]?xp_cmdshell['\"]?\s*,\s*1",  # Explicit enable
        r"EXEC\s+xp_cmdshell",  # Direct execution
        r"value_in_use\s*=\s*1.*xp_cmdshell",  # Config check
    ]
    
    for pattern in patterns:
        if re.search(pattern, sql_content, re.IGNORECASE):
            return True
    
    return False


def check_stored_procedure_logic(sql_content: str) -> float:
    """
    Calculate the ratio of stored procedure logic in SQL file.
    
    Logic lines include: IF, WHILE, BEGIN, END, LOOP, CASE, CURSOR, etc.
    
    Returns ratio (0.0 to 1.0). If > 0.20 (20%), flag as "Database Logic Coupling".
    """
    if not sql_content.strip():
        return 0.0
    
    total_lines = len([l for l in sql_content.split('\n') if l.strip() and not l.strip().startswith('--')])
    
    if total_lines == 0:
        return 0.0
    
    # Logic keywords that indicate business logic in SQL
    logic_keywords = [
        r'\bIF\b', r'\bELSE\b', r'\bWHILE\b', r'\bLOOP\b', r'\bBEGIN\b', r'\bEND\b',
        r'\bCASE\b', r'\bWHEN\b', r'\bCURSOR\b', r'\bFETCH\b', r'\bDECLARE\b',
        r'\bEXEC\b', r'\bEXECUTE\b', r'\bPROCEDURE\b', r'\bFUNCTION\b',
        r'\bTRIGGER\b', r'\bRETURN\b', r'\bRAISE\b', r'\bTHROW\b'
    ]
    
    logic_lines = 0
    for line in sql_content.split('\n'):
        line_upper = line.upper()
        if any(re.search(kw, line_upper) for kw in logic_keywords):
            logic_lines += 1
    
    return logic_lines / total_lines


def scan_legacy_ports(content: str) -> list[dict]:
    """
    Scan content for hardcoded references to insecure legacy ERP/MES ports.
    
    Legacy ports:
    - 3050: Firebird / Fishbowl
    - 3351: Btrieve / Global Shop  
    - 8897: JobBOSS Data Collection
    
    Returns list of found port references.
    """
    found = []
    
    for port, info in LEGACY_ERP_PORTS.items():
        # Look for port in various formats: :3050, port=3050, PORT 3050, etc.
        patterns = [
            rf':\s*{port}\b',
            rf'port\s*[=:]\s*{port}\b',
            rf'PORT\s+{port}\b',
            rf'\b{port}\b.*(?:host|server|connection)',
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found.append({
                    'port': port,
                    'name': info['name'],
                    'risk': info['risk']
                })
                break  # Only count each port once per file
    
    return found


def get_database_summary(db_results: dict[str, Any]) -> str:
    """Get a formatted summary of database analysis."""
    if not db_results:
        return "No database schema files found."
    
    # v2.5: Check for ORM migrations first
    orm_count = db_results.get('orm_migrations_count', 0)
    orm_type = db_results.get('orm_type', None)
    sql_count = db_results.get('schema_files_scanned', 0)
    
    if orm_count > 0 and sql_count == 0:
        return f"Managed via Code-First ORM ({orm_type}). {orm_count} migration files detected."
    
    if orm_count == 0 and sql_count == 0:
        return "No database schema files found."
    
    summary = []
    
    if sql_count > 0:
        summary.append(f"Scanned {sql_count} schema files")
        summary.append(f"Found {db_results['total_tables_found']} tables")
    
    if orm_count > 0:
        summary.append(f"{orm_count} {orm_type} migrations")
    
    if db_results.get('god_tables_count', 0) > 0:
        summary.append(f"⚠️ {db_results['god_tables_count']} 'God Tables' (>{GOD_TABLE_THRESHOLD} columns)")
    
    if db_results.get('heap_tables_count', 0) > 0:
        summary.append(f"🔴 {db_results['heap_tables_count']} 'Heap Tables' (no PRIMARY KEY)")
    
    return " | ".join(summary)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        results = scan_databases(sys.argv[1])
        print(f"\n=== Database Analysis ===")
        print(f"Schema files: {results['schema_files_scanned']}")
        print(f"Tables found: {results['total_tables_found']}")
        print(f"God Tables: {results['god_tables_count']}")
        print(f"Heap Tables: {results['heap_tables_count']}")
        print(f"Remediation hours: {results['total_remediation_hours']}")
        
        if results['risks']:
            print(f"\n=== Risks ===")
            for risk in results['risks']:
                print(f"  [{risk['severity']}] {risk['type']}: {risk['table_name']}")
    else:
        print("Usage: python database_scanner.py <directory>")
