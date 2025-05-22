from app import app as flask_app
import pytest

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client

def test_useradminlogin_page(client):
    response = client.get('/')
    assert response.status_code == 200
