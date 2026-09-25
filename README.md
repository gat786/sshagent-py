# SSH Agent implementation - RFC 9987

This repository is the implementation of [RFC 9987](https://www.rfc-editor.org/info/rfc9987/) in python.

Prerequisites:
* UV installed (https://docs.astral.sh/uv/getting-started/installation/)

You can run this locally by cloning the repository and then

```
uv sync
uv run sshagent-py
```

This will open up a socket endpoint at `/tmp/agent.sock`. You can then set up
SSH_AUTH_SOCK environment variable and then run various commands that interact
with SSH Agent and this implementation will get executed instead of the standard
sshagent that comes in the pack with OpenSSH.

I created this because I wanted to have a GUI option to confirm usage of my keys
when done from a remote vm. The default SSH implementation on MacOS does not
support the `-c` flag. It is built using python and only the SDK itself so it
should run the same on all the operating systems. Please open up a ticket if it
does not work as expected, I will try to resolve the issues as and when they
come.
