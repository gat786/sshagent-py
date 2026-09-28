run:
    uv run --with debugpy sshagent-py

fix-import-sorting:
    uv run ruff check --fix

test:
    uv run python -m unittest discover -s tests -v

test-socat:
    uv run python -m unittest discover -s tests -p "test_socat.py" -v

test-ssh-add:
    uv run python -m unittest discover -s tests -p "test_ssh_add.py" -v
