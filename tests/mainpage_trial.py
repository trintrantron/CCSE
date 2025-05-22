from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client

def test_useradminlogin_page(client):
    response = client.get('/admin/login')
    assert response.status_code == 200
    assert b'<form' in response.data  # Check that the response contains a form
    assert b'Login' in response.data  # Check that the response contains the word 'Login'
