run:
    uv run --with debugpy sshagent-py

test:
    uv run python -m unittest discover -s tests -v

test-socat:
    uv run python -m unittest discover -s tests -p "test_socat.py" -v
