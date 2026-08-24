"""Unit tests for patchi.core.brain.framework"""

import json
import tempfile
import unittest
from pathlib import Path

from patchi.core.brain.framework import FrameworkDetector, StackInfo


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestNodeFrameworks(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _detect(self, pkg: dict) -> StackInfo:
        _write(self.root, "package.json", json.dumps(pkg))
        return FrameworkDetector(self.root).detect()

    def test_detects_express(self):
        stack = self._detect({"dependencies": {"express": "^4.18.0"}})
        names = [f.name for f in stack.frameworks]
        self.assertIn("Express", names)
        self.assertEqual(stack.runtime, "node")

    def test_detects_nextjs(self):
        stack = self._detect({"dependencies": {"next": "^14.0.0", "react": "^18.0.0"}})
        names = [f.name for f in stack.frameworks]
        self.assertIn("Next.js", names)

    def test_detects_fastify(self):
        stack = self._detect({"dependencies": {"fastify": "^4.0.0"}})
        names = [f.name for f in stack.frameworks]
        self.assertIn("Fastify", names)

    def test_detects_react(self):
        stack = self._detect({"dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"}})
        names = [f.name for f in stack.frameworks]
        self.assertIn("React", names)

    def test_detects_nestjs(self):
        stack = self._detect({"dependencies": {"@nestjs/core": "^10.0.0"}})
        names = [f.name for f in stack.frameworks]
        self.assertIn("NestJS", names)

    def test_detects_typescript(self):
        stack = self._detect({"devDependencies": {"typescript": "^5.0.0"}})
        self.assertTrue(stack.has_typescript)

    def test_detects_jest_test_framework(self):
        stack = self._detect({"devDependencies": {"jest": "^29.0.0"}})
        self.assertEqual(stack.test_framework, "Jest")

    def test_detects_npm_lockfile(self):
        _write(self.root, "package-lock.json", "{}")
        _write(self.root, "package.json", json.dumps({"dependencies": {}}))
        stack = FrameworkDetector(self.root).detect()
        self.assertEqual(stack.package_manager, "npm")

    def test_detects_yarn_lockfile(self):
        _write(self.root, "yarn.lock", "")
        _write(self.root, "package.json", json.dumps({"dependencies": {}}))
        stack = FrameworkDetector(self.root).detect()
        self.assertEqual(stack.package_manager, "yarn")

    def test_version_stripped_of_caret(self):
        stack = self._detect({"dependencies": {"express": "^4.18.2"}})
        fw = next((f for f in stack.frameworks if f.name == "Express"), None)
        self.assertIsNotNone(fw)
        self.assertEqual(fw.version, "4.18.2")


class TestPythonFrameworks(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_detects_fastapi(self):
        _write(self.root, "requirements.txt", "fastapi==0.110.0\nuvicorn>=0.24.0\n")
        stack = FrameworkDetector(self.root).detect()
        names = [f.name for f in stack.frameworks]
        self.assertIn("FastAPI", names)
        self.assertEqual(stack.runtime, "python")

    def test_detects_django(self):
        _write(self.root, "requirements.txt", "Django>=4.2\npsycopg2-binary\n")
        stack = FrameworkDetector(self.root).detect()
        names = [f.name for f in stack.frameworks]
        self.assertIn("Django", names)

    def test_detects_flask(self):
        _write(self.root, "requirements.txt", "Flask==3.0.0\nFlask-SQLAlchemy\n")
        stack = FrameworkDetector(self.root).detect()
        names = [f.name for f in stack.frameworks]
        self.assertIn("Flask", names)

    def test_detects_pytest(self):
        _write(self.root, "requirements.txt", "pytest>=7.0\n")
        stack = FrameworkDetector(self.root).detect()
        self.assertEqual(stack.test_framework, "pytest")

    def test_detects_poetry(self):
        _write(self.root, "poetry.lock", "")
        _write(self.root, "pyproject.toml", "[tool.poetry]\nname = 'myapp'\n")
        stack = FrameworkDetector(self.root).detect()
        self.assertEqual(stack.package_manager, "poetry")


class TestDockerAndCI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_detects_dockerfile(self):
        _write(self.root, "Dockerfile", "FROM python:3.11\n")
        stack = FrameworkDetector(self.root).detect()
        self.assertTrue(stack.has_docker)

    def test_detects_docker_compose(self):
        _write(self.root, "docker-compose.yml", "version: '3'\n")
        stack = FrameworkDetector(self.root).detect()
        self.assertTrue(stack.has_docker)

    def test_detects_github_actions(self):
        _write(self.root, ".github/workflows/ci.yml", "on: [push]\n")
        stack = FrameworkDetector(self.root).detect()
        self.assertTrue(stack.has_ci)

    def test_detects_tsconfig(self):
        _write(self.root, "tsconfig.json", '{"compilerOptions": {}}')
        stack = FrameworkDetector(self.root).detect()
        self.assertTrue(stack.has_typescript)


class TestPhpFrameworks(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_detects_laravel(self):
        _write(self.root, "composer.json", json.dumps({"require": {"laravel/framework": "^10.0"}}))
        stack = FrameworkDetector(self.root).detect()
        names = [f.name for f in stack.frameworks]
        self.assertIn("Laravel", names)
        self.assertEqual(stack.runtime, "php")
        self.assertEqual(stack.package_manager, "composer")


if __name__ == "__main__":
    unittest.main()
