#!/bin/sh
# Copyright 2026 fitctl contributors
# SPDX-License-Identifier: Apache-2.0

# Only this immutable inode is executed; per-test bodies are ordinary input files.
exec /bin/sh "${0}.body" "$@"
