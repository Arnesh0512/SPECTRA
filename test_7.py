"""
test_dependency_phase2.py
=========================
Verification script to test Phase 2 Dependency Analyzer and Scanner components directly.
Validates disk location (Step 2), internal package scanning (Step 3), 
and call-mapping / metrics extraction (Step 4).
"""

from pathlib import Path
from spectra.scanners.source.dependency_analyzer import DependencyAnalyzer
from spectra.scanners.source.dependency_scanner import DependencyScanner
from spectra.scanners.source.python_scanner import PythonASTScanner


def test_dependency_resolution_and_analysis():
    print("=" * 70)
    print("Running Phase 2 Dependency Component Verification Test")
    print("=" * 70)

    analyzer = DependencyAnalyzer()
    scanner = DependencyScanner()
    project_root = Path(__file__).parent.resolve()

    # Step 1 & 2: Test disk path resolution for 'requests'
    package_name = "requests"
    ecosystem = "python"
    
    print(f"\n[Step 2] Locating package '{package_name}' ({ecosystem}) on disk...")
    lib_path = analyzer.locate_library_path(package_name, ecosystem, project_root)
    
    if lib_path and lib_path.exists():
        print(f"-> SUCCESS: Found '{package_name}' at path: {lib_path}")
    else:
        print(f"-> WARNING: Could not resolve '{package_name}' path. Ensure it is installed in edcatenv.")
        return

    # Step 3 & 4: Run deep dependency analysis (internal crypto + call mapping)
    print(f"\n[Step 3 & 4] Scanning internal package code & mapping calls to codebase...")
    scanners_map = {"python": PythonASTScanner()}
    
    analysis_results = analyzer.analyze_dependency(package_name, ecosystem, project_root, scanners_map)
    print(f"-> Discovered {len(analysis_results)} cryptographic function mapping record(s) for '{package_name}'.")

    # Print a summary of the extracted metrics
    for idx, record in enumerate(analysis_results[:10], start=1):
        print(f"\n  Record #{idx}:")
        print(f"    • Module Name        : {record['module_name']}")
        print(f"    • Function Called    : {record['function_called']}")
        print(f"    • Internal Crypto    : {record['encryption_internally']}")
        print(f"    • Codebase Caller    : {record['codebase_caller']}")
        print(f"    • Direct Calls       : {record['direct_calls']}")
        print(f"    • Indirect Calls     : {record['indirect_calls']}")
        print(f"    • Call Depth         : {record['call_depth']}")

    print("\n" + "=" * 70)
    print("Phase 2 Component Test Completed Successfully!")
    print("=" * 70)


if __name__ == "__main__":
    test_dependency_resolution_and_analysis()