import pytest
from django.urls import reverse

@pytest.mark.django_db
def test_useradminlogin_template(client):
    url = reverse('admin:login')  # Replace with the actual name of your login URL if different
    response = client.get(url)
    assert response.status_code == 200
    assert 'useradminlogin.html' in [t.name for t in response.templates]
