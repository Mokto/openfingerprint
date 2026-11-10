#!/bin/bash
# Unattended weekly run: checks out origin/main in a throwaway worktree and runs the skill there,
# so the main checkout's branch and uncommitted work are never touched.
# Usage: weekly.sh /path/to/openfingerprint
set -euo pipefail
repo=${1:?usage: weekly.sh /path/to/openfingerprint}
export PATH="/opt/homebrew/opt/node@24/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
# The SSH agent can wait on an approval prompt nobody answers, so every git call in this run
# (including the agent's push) goes over HTTPS with gh's token.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0='url.https://github.com/.insteadOf' GIT_CONFIG_VALUE_0='git@github.com:'
export GIT_CONFIG_KEY_1='credential.https://github.com.helper' GIT_CONFIG_VALUE_1='!gh auth git-credential'

git -C "$repo" fetch --quiet origin
dir=$(mktemp -d /tmp/openfingerprint-stealth-review.XXXXXX)
git -C "$repo" worktree add --quiet --detach "$dir" origin/main
trap 'git -C "$repo" worktree remove --force "$dir"' EXIT

cd "$dir"
# --approve loads the repo's .agents/skills, which print mode can't ask about.
pi --approve -p "/skill:stealth-detection-review This is the unattended weekly run: nobody can answer questions, so decide yourself and finish with a PR or a report." </dev/null
