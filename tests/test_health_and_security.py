import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _build_test_app(tmp_path):
    os.environ['DATABASE_URL'] = f"sqlite:///{tmp_path}/test.db"
    os.environ['SECRET_KEY'] = 'x' * 40
    os.environ['ENVIRONMENT'] = 'development'

    import importlib
    import app as app_module
    importlib.reload(app_module)

    app_module.app.config.update(TESTING=True)
    with app_module.app.app_context():
        app_module.db.drop_all()
        app_module.db.create_all()
        app_module.ensure_default_groups()
        app_module.ensure_admin_user()

    return app_module.app


@pytest.fixture()
def client(tmp_path):
    flask_app = _build_test_app(tmp_path)
    with flask_app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json['status'] == 'ok'


def test_ready_endpoint(client):
    response = client.get('/ready')
    assert response.status_code == 200
    assert response.json['database'] == 'ok'


def test_csrf_rejects_post_without_token(client):
    response = client.post('/login', data={'email': 'none@test.local', 'password': 'bad'})
    assert response.status_code == 400
