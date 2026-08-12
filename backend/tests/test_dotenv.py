import os
import subprocess
import sys


def test_package_initialization_loads_backend_dotenv(tmp_path):
    package = tmp_path / "app"
    package.mkdir()
    source = (__import__("pathlib").Path(__file__).resolve().parents[1] / "app" / "__init__.py").read_text(encoding="utf-8")
    (package / "__init__.py").write_text(source, encoding="utf-8")
    (tmp_path / ".env").write_text("UNIPHISHGUARD_DOTENV_TEST=loaded\n", encoding="utf-8")
    environment = dict(os.environ)
    environment.pop("UNIPHISHGUARD_DOTENV_TEST", None)
    environment["PYTHONPATH"] = str(tmp_path)
    output = subprocess.check_output(
        [sys.executable, "-c", "import app, os; print(os.getenv('UNIPHISHGUARD_DOTENV_TEST', 'missing'))"],
        env=environment,
        text=True,
        cwd=tmp_path,
    )
    assert output.strip() == "loaded"
