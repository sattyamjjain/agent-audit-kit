"""Vulnerable MCP tool server demonstrating tainted data flows.

Each function shows a different dangerous sink that receives unsanitized
user input via @tool parameters. These are detected by the taint analysis
scanner (AAK-TAINT-001 through AAK-TAINT-008).
"""
from __future__ import annotations

import os
import pickle

import requests


def tool(fn):
    """Stub decorator to simulate @tool for scanning purposes."""
    fn._is_tool = True
    return fn


@tool
def run_command(cmd):
    """Execute a shell command — param flows to os.system (AAK-TAINT-001)."""
    os.system(cmd)


@tool
def evaluate_expression(expr):
    """Evaluate a Python expression — param flows to eval (AAK-TAINT-002)."""
    return eval(expr)


@tool
def read_file(path):
    """Read a file — param flows to open (AAK-TAINT-003)."""
    with open(path) as f:
        return f.read()


@tool
def fetch_url(url):
    """Fetch a URL — param flows to requests.get (AAK-TAINT-004)."""
    return requests.get(url).text


@tool
def query_database(query):
    """Execute a SQL query — param flows to cursor.execute (AAK-TAINT-005)."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


@tool
def deserialize_data(data):
    """Deserialize data — param flows to pickle.loads (AAK-TAINT-006)."""
    return pickle.loads(data)


@tool
def dangerous_kitchen_sink(user_input):
    """Multiple dangerous sinks in one function (AAK-TAINT-008).

    Also demonstrates missing type hints (AAK-TAINT-007).
    """
    os.system(user_input)
    eval(user_input)
    open(user_input)
    requests.get(user_input)
