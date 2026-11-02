
"""
Declarative taint registry for Vulnexa.

Lists the taint sources, security sinks, and sanitizers used by
the taint analysis. The lists are intentionally small and
controlled:

- Sources match the framework or module object itself (for
  example the name "request" for Flask request data), never a
  variable merely because of its name.
- Sanitizers are sink-specific. shlex.quote and shlex.join are
  recognized only for shell-command sinks. int(), float(), and
  html.escape() are deliberately NOT treated as sanitizers:
  they do not make data safe for every sink, so taint is
  preserved whenever safety cannot be established.
- There is no sanitizer for code-execution sinks (eval/exec)
  or deserialization sinks (pickle); the safe fix is not to
  reach those sinks with untrusted data at all.

This module only reads the AST; scanned source code is never
executed.
"""

from vulnexa.analysis.taint_models import (
    CONDITION_SHELL_TRUE,
    SINK_CODE_EXECUTION,
    SINK_DESERIALIZATION,
    SINK_SHELL_COMMAND,
    TaintSanitizer,
    TaintSink,
    TaintSource,
)


SOURCES = (
    TaintSource(
        source_id="input",
        kind="standard-input",
        match_call_names=("input",),
    ),
    TaintSource(
        source_id="sys.argv",
        kind="command-line",
        match_attribute_paths=("sys.argv",),
    ),
    TaintSource(
        source_id="os.environ",
        kind="environment",
        match_attribute_paths=("os.environ",),
    ),
    TaintSource(
        source_id="sys.stdin",
        kind="standard-input",
        match_attribute_paths=("sys.stdin",),
    ),
    TaintSource(
        source_id="request.args",
        kind="http-request",
        match_attribute_paths=("request.args",),
    ),
    TaintSource(
        source_id="request.form",
        kind="http-request",
        match_attribute_paths=("request.form",),
    ),
    TaintSource(
        source_id="request.json",
        kind="http-request",
        match_attribute_paths=("request.json",),
    ),
)


SINKS = (
    TaintSink(
        rule_id="TAINT-001",
        sink_kind=SINK_CODE_EXECUTION,
        title="Tainted data reaches eval()/exec()",
        severity="WARNING",
        message=(
            "Data from an untrusted source reaches eval() or exec(). "
            "An attacker who controls the string can run arbitrary code."
        ),
        recommendation=(
            "Avoid evaluating untrusted input. Restructure the "
            "application so dynamic behavior does not require "
            "executing strings."
        ),
        match_call_names=("eval", "exec"),
    ),
    TaintSink(
        rule_id="TAINT-002",
        sink_kind=SINK_SHELL_COMMAND,
        title="Tainted data reaches os.system()/os.popen()",
        severity="HIGH",
        message=(
            "Data from an untrusted source reaches a shell command "
            "through os.system() or os.popen(). This enables shell "
            "injection."
        ),
        recommendation=(
            "Avoid os.system() with untrusted input. Prefer the "
            "subprocess module with a list of arguments and "
            "shell=False."
        ),
        match_attribute_paths=("os.system", "os.popen"),
    ),
    TaintSink(
        rule_id="TAINT-003",
        sink_kind=SINK_SHELL_COMMAND,
        title="Tainted data reaches subprocess with shell=True",
        severity="HIGH",
        message=(
            "Data from an untrusted source reaches a subprocess call "
            "executed through the system shell. This enables shell "
            "injection."
        ),
        recommendation=(
            "Use shell=False (the default) and pass the command as "
            "a list of arguments."
        ),
        match_attribute_paths=(
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        ),
        condition=CONDITION_SHELL_TRUE,
    ),
    TaintSink(
        rule_id="TAINT-004",
        sink_kind=SINK_DESERIALIZATION,
        title="Tainted data reaches pickle deserialization",
        severity="HIGH",
        message=(
            "Data from an untrusted source is deserialized with "
            "pickle. Crafted data can execute arbitrary code."
        ),
        recommendation=(
            "Never deserialize untrusted data with pickle. Use a "
            "safe serialization format such as JSON instead."
        ),
        match_attribute_paths=("pickle.load", "pickle.loads"),
    ),
)


SANITIZERS = (
    TaintSanitizer(
        sanitizer_id="shlex.quote",
        clears_sinks=frozenset({SINK_SHELL_COMMAND}),
        match_attribute_paths=("shlex.quote",),
    ),
    TaintSanitizer(
        sanitizer_id="shlex.join",
        clears_sinks=frozenset({SINK_SHELL_COMMAND}),
        match_attribute_paths=("shlex.join",),
    ),
)


def get_sources():
    return SOURCES


def get_sinks():
    return SINKS


def get_sanitizers():
    return SANITIZERS


def match_source(node, import_map=None):
    """
    Return the first source whose matcher accepts the node, or
    None when the node is not a source.
    """

    for source in SOURCES:
        if source.matches(node, import_map):
            return source

    return None


def match_sinks(node, import_map=None):
    """
    Return every sink whose matcher accepts the node.
    """

    return tuple(
        sink for sink in SINKS if sink.matches(node, import_map)
    )


def match_sanitizer(node, import_map=None):
    """
    Return the first sanitizer whose matcher accepts the node,
    or None when the node is not a sanitizer.
    """

    for sanitizer in SANITIZERS:
        if sanitizer.matches(node, import_map):
            return sanitizer

    return None
