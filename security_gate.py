#!/usr/bin/env python3
"""
Root wrapper for scripts/security_gate.py
Enables direct execution via `python security_gate.py` from repository root.
"""
import sys
import os

# Delegate execution directly to the modular implementation
script_path = os.path.join(os.path.dirname(__file__), "scripts", "security_gate.py")
if __name__ == "__main__":
    with open(script_path, "r", encoding="utf-8") as f:
        code = compile(f.read(), script_path, "exec")
        exec(code, globals())
