# Run unit tests (no Docker / NET_ADMIN required)
test:
    uv run pytest -v

# Run container integration tests (requires Docker + NET_ADMIN)
test-container:
    uv run pytest -v -m container

# Run all tests (unit + container)
test-all: test test-container
