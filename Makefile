# A dev agent on its own socket, next to the installed one:
#   make run-test-agent   # terminal 1
#   make run-test         # terminal 2

SOCKET ?= $(or $(TMPDIR),/tmp/)whoami-dev.sock
# the agent that holds the keys: the installed whoami's upstream, else the current agent;
# the installed whoami is the current agent, so chaining to it would show two pickers
UPSTREAM ?= $(or $(shell launchctl print gui/$$(id -u)/org.nixos.whoami 2>/dev/null \
	| sed -n 's/.*WHOAMI_UPSTREAM => //p'),$(SSH_AUTH_SOCK))
# the destination and repository the test client asks for, as git would
HOST ?= git@github.com
REPO ?= IAmRadek/whoami.git

.PHONY: run-test-agent run-test

run-test-agent:
	@echo "upstream $(UPSTREAM)"
	WHOAMI_UPSTREAM=$(UPSTREAM) WHOAMI_SOCKET=$(SOCKET) cargo run

# runs in /tmp so a directory rule for this checkout does not answer instead of the picker;
# stdin is empty, so the server lists its refs and exits;
# IdentityAgent on the command line wins over one in ~/.ssh/config, which wins over SSH_AUTH_SOCK
run-test:
	cd /tmp && ssh -o IdentityAgent=$(SOCKET) $(HOST) "git-upload-pack '$(REPO)'" </dev/null >/dev/null
