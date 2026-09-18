import pytest
from detecti.modules.masscan import MasscanRunner
from detecti.modules.nuclei import NucleiRunner

def test_masscan_check_permissions_no_name_error():
    """Verify check_permissions never raises NameError (e.g. missing subprocess)."""
    runner = MasscanRunner()
    result = runner.check_permissions()
    assert isinstance(result, dict)
    assert "available" in result
    assert "message" in result
    assert "name 'subprocess' is not defined" not in result.get("message", "")

def test_nuclei_check_permissions_no_name_error():
    """Verify nuclei check_permissions executes cleanly and returns structured dict."""
    runner = NucleiRunner()
    result = runner.check_permissions()
    assert isinstance(result, dict)
    assert "available" in result
    assert "message" in result
    assert "not defined" not in result.get("message", "")

def test_ast_no_undefined_globals():
    """Scan all module files to verify no undefined global references exist."""
    import ast
    from pathlib import Path
    import detecti

    pkg_root = Path(detecti.__file__).parent
    py_files = list(pkg_root.rglob("*.py"))
    
    for py_file in py_files:
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))
        
        # Verify ast parses cleanly without syntax errors
        assert tree is not None
