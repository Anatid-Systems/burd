import contextlib
import io


@contextlib.contextmanager
def capture_output():
    """Redirect stdout and stderr into a StringIO buffer."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf
