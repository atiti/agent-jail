import shlex


class ShellAnalysisError(ValueError):
    pass


def _tokenize(script):
    lexer = shlex.shlex(script, posix=True, punctuation_chars="|&;()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def analyze_shell_script(script):
    try:
        tokens = _tokenize(script)
    except ValueError as exc:
        raise ShellAnalysisError(str(exc)) from exc

    def parse_sequence(index, end_token=None):
        commands = []
        pipelines = []
        current = []
        pipeline = []

        def flush_command():
            nonlocal current
            if current:
                pipeline.append(current)
                commands.append(current)
                current = []

        def flush_pipeline():
            nonlocal pipeline
            flush_command()
            if pipeline:
                pipelines.append(pipeline)
                pipeline = []

        while index < len(tokens):
            token = tokens[index]
            if end_token and token == end_token:
                flush_pipeline()
                return commands, pipelines, index + 1
            if token in {"&&", "||", ";"}:
                flush_pipeline()
                index += 1
                continue
            if token == "|":
                flush_command()
                index += 1
                continue
            if token == "$" and index + 1 < len(tokens) and tokens[index + 1] == "(":
                nested_commands, nested_pipelines, index = parse_sequence(index + 2, ")")
                commands.extend(nested_commands)
                pipelines.extend(nested_pipelines)
                continue
            if token == "(":
                nested_commands, nested_pipelines, index = parse_sequence(index + 1, ")")
                commands.extend(nested_commands)
                pipelines.extend(nested_pipelines)
                continue
            if token == ")":
                raise ShellAnalysisError("unexpected closing parenthesis")
            current.append(token)
            index += 1

        if end_token:
            raise ShellAnalysisError("unclosed parenthesis")
        flush_pipeline()
        return commands, pipelines, index

    commands, pipelines, index = parse_sequence(0)
    if index != len(tokens):
        raise ShellAnalysisError("trailing shell tokens")
    return {"tokens": tokens, "commands": commands, "pipelines": pipelines}
