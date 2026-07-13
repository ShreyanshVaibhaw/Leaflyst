from abx_api.main import app
from abx_api.settings import settings
from fastapi.testclient import TestClient


def test_otlp_body_is_rejected_before_authentication_and_parsing() -> None:
    response = TestClient(app).post(
        "/v1/otlp/traces",
        content=b"x" * (settings.otlp_body_max_bytes + 1),
        headers={
            "Authorization": "Bearer invalid",
            "Content-Type": "application/x-protobuf",
        },
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "request body too large"}
