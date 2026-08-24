"""Unit tests for patchi.core.brain.route_mapper"""

import tempfile
import unittest
from pathlib import Path

from patchi.core.brain.framework import FrameworkInfo, StackInfo
from patchi.core.brain.route_mapper import (
    RouteMapper,
    _extract_django,
    _extract_express,
    _extract_fastapi,
    _extract_flask,
    _extract_laravel,
    _extract_nextjs_file_routes,
)


def _make_stack(*framework_names: str) -> StackInfo:
    stack = StackInfo()
    for name in framework_names:
        stack.frameworks.append(
            FrameworkInfo(
                name=name,
                language="",
                version="",
                config_file="",
                confidence=1.0,
            )
        )
    return stack


class TestFastAPIExtraction(unittest.TestCase):
    def test_get_route(self):
        src = "@app.get('/users')\ndef list_users():\n    return []\n"
        routes = _extract_fastapi(src, "routes.py")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].method, "GET")
        self.assertEqual(routes[0].path, "/users")
        self.assertEqual(routes[0].handler, "list_users")
        self.assertEqual(routes[0].framework, "FastAPI")

    def test_post_route(self):
        src = "@router.post('/users')\nasync def create_user(data: UserIn):\n    pass\n"
        routes = _extract_fastapi(src, "users.py")
        self.assertEqual(routes[0].method, "POST")
        self.assertTrue(routes[0].handler == "create_user")

    def test_websocket_route(self):
        src = "@app.websocket('/ws')\nasync def ws_endpoint(ws):\n    pass\n"
        routes = _extract_fastapi(src, "ws.py")
        self.assertEqual(routes[0].method, "WEBSOCKET")

    def test_delete_route(self):
        src = "@app.delete('/users/{id}')\nasync def delete_user(id: int):\n    pass\n"
        routes = _extract_fastapi(src, "users.py")
        self.assertEqual(routes[0].method, "DELETE")
        self.assertIn("{id}", routes[0].path)

    def test_auth_detection_via_depends(self):
        src = (
            "@app.get('/me')\n"
            "async def get_me(\n"
            "    current_user = Depends(get_current_user)\n"
            "):\n    pass\n"
        )
        routes = _extract_fastapi(src, "users.py")
        self.assertTrue(routes[0].auth_required)

    def test_multiple_routes(self):
        src = (
            "@app.get('/items')\ndef list_items(): pass\n\n"
            "@app.post('/items')\ndef create_item(): pass\n"
        )
        routes = _extract_fastapi(src, "items.py")
        self.assertEqual(len(routes), 2)
        methods = {r.method for r in routes}
        self.assertEqual(methods, {"GET", "POST"})


class TestFlaskExtraction(unittest.TestCase):
    def test_get_route(self):
        src = "@app.route('/home')\ndef home():\n    return 'ok'\n"
        routes = _extract_flask(src, "views.py")
        self.assertTrue(any(r.path == "/home" for r in routes))

    def test_multi_method_route(self):
        src = "@app.route('/login', methods=['GET', 'POST'])\ndef login(): pass\n"
        routes = _extract_flask(src, "auth.py")
        methods = {r.method for r in routes}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_login_required_detection(self):
        src = "@app.route('/dashboard')\n@login_required\ndef dashboard(): pass\n"
        routes = _extract_flask(src, "views.py")
        self.assertTrue(any(r.auth_required for r in routes))

    def test_blueprint_route(self):
        src = "@bp.route('/api/users')\ndef get_users(): pass\n"
        routes = _extract_flask(src, "api.py")
        self.assertTrue(any(r.path == "/api/users" for r in routes))


class TestExpressExtraction(unittest.TestCase):
    def test_get_route(self):
        src = "app.get('/users', (req, res) => res.json([]));\n"
        routes = _extract_express(src, "routes.js")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].method, "GET")
        self.assertEqual(routes[0].path, "/users")

    def test_post_route(self):
        src = "router.post('/users', createUser);\n"
        routes = _extract_express(src, "users.js")
        self.assertEqual(routes[0].method, "POST")

    def test_all_route(self):
        src = "app.all('/api/*', logger);\n"
        routes = _extract_express(src, "middleware.js")
        self.assertEqual(routes[0].method, "ALL")

    def test_auth_middleware_detected(self):
        src = "router.get('/profile', authenticate, getProfile);\n"
        routes = _extract_express(src, "profile.js")
        self.assertTrue(routes[0].auth_required)

    def test_multiple_routes(self):
        src = (
            "router.get('/items', listItems);\n"
            "router.post('/items', createItem);\n"
            "router.delete('/items/:id', deleteItem);\n"
        )
        routes = _extract_express(src, "items.js")
        self.assertEqual(len(routes), 3)


class TestDjangoExtraction(unittest.TestCase):
    def test_path_route(self):
        src = "path('users/', views.UserListView.as_view()),\n"
        routes = _extract_django(src, "urls.py")
        self.assertEqual(len(routes), 1)
        self.assertIn("users/", routes[0].path)

    def test_re_path_route(self):
        src = "re_path(r'^users/(?P<pk>[0-9]+)/$', views.user_detail),\n"
        routes = _extract_django(src, "urls.py")
        self.assertEqual(len(routes), 1)

    def test_handler_extracted(self):
        src = "path('login/', auth_views.LoginView.as_view()),\n"
        routes = _extract_django(src, "urls.py")
        self.assertIn("auth_views", routes[0].handler)


class TestLaravelExtraction(unittest.TestCase):
    def test_get_route(self):
        src = "Route::get('/users', [UserController::class, 'index']);\n"
        routes = _extract_laravel(src, "web.php")
        self.assertEqual(routes[0].method, "GET")
        self.assertEqual(routes[0].path, "/users")

    def test_post_route(self):
        src = "Route::post('/users', 'UserController@store');\n"
        routes = _extract_laravel(src, "web.php")
        self.assertEqual(routes[0].method, "POST")
        self.assertEqual(routes[0].handler, "UserController@store")

    def test_auth_middleware(self):
        src = "Route::get('/profile', [ProfileController::class, 'show'])->middleware('auth');\n"
        routes = _extract_laravel(src, "web.php")
        self.assertTrue(routes[0].auth_required)


class TestNextJsFileRoutes(unittest.TestCase):
    def test_pages_api_route(self):
        routes = _extract_nextjs_file_routes("pages/api/users.ts", Path("/fake"))
        self.assertEqual(len(routes), 1)
        self.assertIn("/api/users", routes[0].path)

    def test_pages_api_nested(self):
        routes = _extract_nextjs_file_routes("pages/api/users/[id].ts", Path("/fake"))
        self.assertIn(":id", routes[0].path)

    def test_app_router_route(self):
        routes = _extract_nextjs_file_routes("app/api/users/route.ts", Path("/fake"))
        self.assertEqual(len(routes), 1)
        self.assertIn("/api/users", routes[0].path)


class TestRouteMapperIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write(self, rel: str, content: str):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def test_extracts_fastapi_routes_end_to_end(self):
        from patchi.core import config as cfg
        from patchi.core.brain.scanner import FileScanner

        cfg.init_project(self.root)

        self._write(
            "src/main.py",
            "@app.get('/health')\ndef health_check():\n    return {'ok': True}\n"
            "@app.post('/users')\nasync def create_user():\n    pass\n",
        )
        files = FileScanner(self.root).scan()
        stack = _make_stack("FastAPI")
        mapper = RouteMapper(self.root, stack)
        routes = mapper.extract(files)
        self.assertGreater(len(routes), 0)
        paths = [r.path for r in routes]
        self.assertIn("/health", paths)
        self.assertIn("/users", paths)

    def test_deduplicates_routes(self):
        from patchi.core import config as cfg
        from patchi.core.brain.scanner import FileScanner

        cfg.init_project(self.root)

        # Same route defined twice (copy-paste mistake)
        self._write(
            "src/routes.js", "router.get('/users', listUsers);\nrouter.get('/users', listUsers);\n"
        )
        files = FileScanner(self.root).scan()
        stack = _make_stack("Express")
        mapper = RouteMapper(self.root, stack)
        routes = mapper.extract(files)
        user_routes = [r for r in routes if r.path == "/users" and r.method == "GET"]
        self.assertEqual(len(user_routes), 1)


if __name__ == "__main__":
    unittest.main()
