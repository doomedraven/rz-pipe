from shutil import which
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch
import pytest
from rzpipe import open_sync


class MockPipe:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read_count = 0
        self.closed = False

    def close(self):
        self.closed = True

    def read(self, size=4096):
        if self.read_count < len(self.chunks):
            res = self.chunks[self.read_count]
            self.read_count += 1
            if isinstance(res, Exception):
                raise res
            return res
        return b""


def create_mock_open_instance():
    instance = open_sync.open.__new__(open_sync.open)
    instance.process = MagicMock()
    instance.process.stdin = MagicMock()
    return instance


def test_cmd_process_normal_output():
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([b"hello world\n\x00"])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "hello world\n"


def test_cmd_process_printf_after_null():
    """
    Test case for Issue #60: Rizin prints debug messages via printf after command output \x00.
    The reader loop must not hang and should correctly extract command output up to \x00.
    """
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([b"command output\x00extra printf debug message\n"])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "command output"


def test_cmd_process_multichunk_printf():
    """
    Test multichunk output where null byte and printf text are in the final chunk.
    """
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([
        b"first line\n",
        b"second line\n\x00printf debug output\n"
    ])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "first line\nsecond line\n"


def test_cmd_process_blocking_io_error():
    """
    Ensure BlockingIOError during stdout reading is handled gracefully without unbound variable errors.
    """
    instance = create_mock_open_instance()
    mock_stdout = MockPipe([BlockingIOError(), b"result\x00"])
    mock_stderr = MockPipe([])

    instance.process.stdout = mock_stdout
    instance.process.stderr = mock_stderr

    result = instance._cmd_process("px 1")
    assert result == "result"


def test_cmd_process_nonblocking_none_then_output():
    """
    Non-blocking raw FileIO streams return None on EAGAIN (distinct from b"" EOF).
    """
    instance = create_mock_open_instance()
    instance.process.stdout = MockPipe([None, b"ok\x00"])
    instance.process.stderr = MockPipe([])

    result = instance._cmd_process("px 1")
    assert result == "ok"


def test_cmd_process_stdout_eof_raises():
    """
    Ensure EOF (b"") on stdout raises BrokenPipeError instead of spinning forever.
    """
    instance = create_mock_open_instance()
    instance.process.stdout = MockPipe([None, b""])
    instance.process.stderr = MockPipe([b"fatal error\n"])
    instance.process.poll.return_value = -11

    with pytest.raises(BrokenPipeError, match=r"exit code -11.*fatal error"):
        instance._cmd_process("px 1")


def test_cmd_process_eof_waits_for_exit_code_and_truncates_stderr():
    """
    Ensure EOF falls back to bounded wait() when poll() is None and keeps tail of large stderr.
    """
    instance = create_mock_open_instance()
    instance.process.stdout = MockPipe([b""])
    instance.process.stderr = MockPipe([b"A" * 5000 + b"TAIL_MARKER\n"])
    instance.process.poll.return_value = None
    instance.process.wait.return_value = -9

    with pytest.raises(BrokenPipeError) as exc_info:
        instance._cmd_process("px 1")

    msg = str(exc_info.value)
    assert "exit code -9" in msg
    assert "TAIL_MARKER" in msg
    assert len(msg) <= 4200
    instance.process.wait.assert_called_once()


def test_open_startup_nonblocking_failure_cleans_up():
    """
    Ensure startup failure after Popen (e.g. non-blocking setup failure) cleans up the child.
    """
    spawned = []
    real_popen = subprocess.Popen

    script = (
        "import sys; "
        "sys.stdout.buffer.write(b'\\x00'); sys.stdout.buffer.flush(); "
        "sys.stdin.buffer.readline()"
    )

    def fake_popen(cmd, **kwargs):
        proc = real_popen([sys.executable, "-c", script], **kwargs)
        spawned.append(proc)
        return proc

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with patch.object(
            open_sync.open, "_open__make_non_blocking", return_value=False
        ):
            with pytest.raises(Exception, match=r"non-blocking"):
                open_sync.open("dummy")

    assert len(spawned) == 1
    proc = spawned[0]
    assert proc.poll() is not None
    assert proc.stdin.closed
    assert proc.stdout.closed
    assert proc.stderr.closed


def test_double_quit_and_cmd_after_quit():
    """
    Ensure quit() is idempotent (e.g. manual quit inside a with-block)
    and subsequent cmd() calls raise BrokenPipeError instead of AttributeError.
    """
    spawned = []
    real_popen = subprocess.Popen

    script = (
        "import sys; "
        "sys.stdout.buffer.write(b'\\x00'); sys.stdout.buffer.flush(); "
        "sys.stdin.buffer.readline(); "
        "sys.stdout.buffer.write(b'\\x00'); sys.stdout.buffer.flush()"
    )

    def fake_popen(cmd, **kwargs):
        proc = real_popen([sys.executable, "-c", script], **kwargs)
        spawned.append(proc)
        return proc

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with open_sync.open("dummy") as rz:
            rz.quit()
            with pytest.raises(BrokenPipeError, match=r"not running"):
                rz.cmd("i")

    assert len(spawned) == 1
    proc = spawned[0]
    assert proc.poll() is not None
    assert proc.stdin.closed
    assert proc.stdout.closed
    assert proc.stderr.closed


def test_open_startup_eof_raises_and_reaps():
    """
    Ensure early child exit before initial null byte raises BrokenPipeError,
    reaps the child process, and closes pipes instead of busy-looping.
    """
    spawned = []
    real_popen = subprocess.Popen

    def fake_popen(cmd, **kwargs):
        proc = real_popen(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('startup failed\\n'); sys.exit(1)",
            ],
            **kwargs,
        )
        spawned.append(proc)
        return proc

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with pytest.raises(BrokenPipeError, match=r"exit code 1.*startup failed"):
            open_sync.open("/nonexistent/binary")

    assert len(spawned) == 1
    proc = spawned[0]
    assert proc.poll() == 1
    assert proc.stdin.closed
    assert proc.stdout.closed
    assert proc.stderr.closed


def test_cleanup_startup_process_timeout_drains_stderr():
    """
    Ensure timeout during non-blocking startup cleanup closes stdin, kills the child,
    drains any remaining stderr, and deletes self.process.
    """
    instance = create_mock_open_instance()
    proc = instance.process
    proc.stdin.closed = False
    proc.stdin.close.side_effect = lambda: setattr(proc.stdin, "closed", True)
    proc.stdout.closed = False
    proc.stderr = MockPipe([b"extra stderr\n"])
    proc.poll.return_value = None
    proc.returncode = -9

    rc, stderr_data = instance._cleanup_startup_process(
        err_tail=bytearray(b"partial "), timeout=0.0
    )

    assert rc == -9
    assert stderr_data == b"partial extra stderr\n"
    proc.stdin.close.assert_called_once()
    proc.kill.assert_called_once()
    proc.wait.assert_called_once()
    assert proc.stderr.closed
    assert not hasattr(instance, "process")


def test_cleanup_startup_process_exits_after_draining_stderr():
    """
    Ensure startup cleanup returns immediately without killing when the child exits
    while draining non-blocking stderr.
    """
    instance = create_mock_open_instance()
    proc = instance.process
    proc.stdin.closed = False
    proc.stdout.closed = False
    proc.stderr = MockPipe([b"first\n", None, b"second\n"])
    proc.stderr.closed = False
    proc.poll.side_effect = [None, 1]
    proc.returncode = 1

    rc, stderr_data = instance._cleanup_startup_process(timeout=1.0)

    assert rc == 1
    assert stderr_data == b"first\nsecond\n"
    proc.kill.assert_not_called()
    assert not hasattr(instance, "process")


def test_open_startup_eof_hung_child_timeout_reaps_and_drains_stderr():
    """
    Real Popen regression test: child closes stdout without '\\x00', writes to stderr,
    and hangs. Startup cleanup must kill it, drain stderr without duplication, and close pipes.
    """
    spawned = []
    real_popen = subprocess.Popen

    script = (
        "import os, sys, time; "
        "sys.stderr.buffer.write(b'hung stderr\\n'); sys.stderr.buffer.flush(); "
        "os.close(1); "
        "time.sleep(30)"
    )

    def fake_popen(cmd, **kwargs):
        proc = real_popen([sys.executable, "-c", script], **kwargs)
        spawned.append(proc)
        return proc

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with patch.object(open_sync.open, "_STARTUP_CLEANUP_TIMEOUT", 0.1):
            with pytest.raises(BrokenPipeError, match=r"hung stderr") as exc_info:
                open_sync.open("dummy")

    assert str(exc_info.value).count("hung stderr") == 1
    assert len(spawned) == 1
    proc = spawned[0]
    assert proc.poll() is not None
    assert proc.stdin.closed
    assert proc.stdout.closed
    assert proc.stderr.closed


def test_context_manager_cleanup_after_child_exit():
    """
    Ensure exiting a context manager after the child terminates mid-command
    propagates the original BrokenPipeError and closes all pipes cleanly.
    """
    spawned = []
    real_popen = subprocess.Popen

    script = (
        "import sys; "
        "sys.stdout.buffer.write(b'banner\\x00'); sys.stdout.buffer.flush(); "
        "sys.stdin.buffer.readline(); "
        "sys.stderr.buffer.write(b'crashed\\n'); sys.stderr.buffer.flush(); "
        "sys.exit(2)"
    )

    def fake_popen(cmd, **kwargs):
        proc = real_popen([sys.executable, "-c", script], **kwargs)
        spawned.append(proc)
        return proc

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with pytest.raises(BrokenPipeError, match=r"crashed"):
            with open_sync.open("dummy") as rz:
                rz.cmd("aaa")

    assert len(spawned) == 1
    proc = spawned[0]
    assert proc.poll() is not None
    assert proc.stdin.closed
    assert proc.stdout.closed
    assert proc.stderr.closed


@pytest.mark.skipif(which("rizin") is None, reason="rizin not found in PATH")
def test_real_rizin_startup_eof_and_mid_session_exit():
    with pytest.raises(BrokenPipeError, match=r"exit code 1"):
        open_sync.open("/nonexistent/path/that/does/not/exist")

    with open_sync.open("--") as rz:
        with pytest.raises(BrokenPipeError):
            rz.cmd("q!!")


def test_cmd_process_large_multichunk_no_sleep_throttle():
    """
    Reading 128 chunks (512 KiB) must not sleep 10 ms between ready chunks.
    Previously 128 * 0.01 s = >= 1.28 s; now completes in a few milliseconds.
    """
    instance = create_mock_open_instance()
    payload_chunk = b"A" * 4096
    instance.process.stdout = MockPipe([payload_chunk] * 128 + [b"\x00"])
    instance.process.stderr = MockPipe([])

    t0 = time.perf_counter()
    result = instance._cmd_process("aflj")
    elapsed = time.perf_counter() - t0

    assert len(result) == 128 * 4096
    assert elapsed < 0.5


def test_cmd_process_select_fast_small_commands_and_ret_stderr():
    """
    Real subprocess pipe: 50 round-trip commands must wake immediately via poll/select
    (well below the legacy 50 * 10 ms = 500 ms sleep floor), and ret_stderr=True must
    capture stderr emitted alongside the stdout terminator without spinning on stderr EOF.
    """
    script = (
        "import sys\n"
        "sys.stdout.buffer.write(b'\\x00')\n"
        "sys.stdout.buffer.flush()\n"
        "for line in sys.stdin.buffer:\n"
        "    cmd = line.strip()\n"
        "    if cmd == b'q':\n"
        "        sys.stdout.buffer.write(b'\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "        break\n"
        "    if cmd == b'err':\n"
        "        sys.stderr.buffer.write(b'ERROR: bad\\n')\n"
        "        sys.stderr.buffer.flush()\n"
        "        sys.stdout.buffer.write(b'\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "    elif cmd == b'big':\n"
        "        sys.stdout.buffer.write(b'X' * 524288 + b'\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "    else:\n"
        "        sys.stdout.buffer.write(b'ok\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
    )
    real_popen = subprocess.Popen

    def fake_popen(cmd, **kwargs):
        return real_popen([sys.executable, "-c", script], **kwargs)

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with open_sync.open("dummy") as rz:
            t0 = time.perf_counter()
            for _ in range(50):
                assert rz.cmd("ping") == "ok"
            small_elapsed = time.perf_counter() - t0
            if sys.platform != "win32":
                assert small_elapsed < 0.35

            t0 = time.perf_counter()
            big = rz.cmd("big")
            big_elapsed = time.perf_counter() - t0
            assert len(big) == 524288
            assert big_elapsed < 0.5

            err_out = rz.cmd("err", ret_stderr=True)
            assert "ERROR: bad" in err_out


def test_cmd_process_ret_stderr_drain_on_nul_and_embedded_nul():
    """
    ret_stderr=True must capture stderr emitted alongside stdout '\\x00' and must not
    desynchronize subsequent commands if stderr contains an embedded NUL byte.
    """
    instance = create_mock_open_instance()
    instance.process.stdout = MockPipe([b"out\n\x00"])
    instance.process.stderr = MockPipe([b"WARN: detail\n"])
    assert instance._cmd_process("cmd", ret_stderr=True) == "out\nWARN: detail\n"

    script = (
        "import os, sys\n"
        "sys.stdout.buffer.write(b'\\x00')\n"
        "sys.stdout.buffer.flush()\n"
        "for line in sys.stdin.buffer:\n"
        "    cmd = line.strip()\n"
        "    if cmd == b'q':\n"
        "        sys.stdout.buffer.write(b'\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "        break\n"
        "    if cmd == b'nul_err':\n"
        "        sys.stderr.buffer.write(b'WARN\\x00TAIL\\n')\n"
        "        sys.stderr.buffer.flush()\n"
        "        sys.stdout.buffer.write(b'primary\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "    elif cmd == b'close_err':\n"
        "        os.close(2)\n"
        "        sys.stdout.buffer.write(b'after_close\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "    else:\n"
        "        sys.stdout.buffer.write(b'synced\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
    )
    real_popen = subprocess.Popen

    def fake_popen(cmd, **kwargs):
        return real_popen([sys.executable, "-c", script], **kwargs)

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with open_sync.open("dummy") as rz:
            out = rz.cmd("nul_err", ret_stderr=True)
            assert "primary" in out
            assert "WARN" in out
            assert rz.cmd("ping") == "synced"
            assert rz.cmd("close_err", ret_stderr=True) == "after_close"
            assert rz.cmd("ping", ret_stderr=True) == "synced"


def test_large_stderr_does_not_deadlock_startup_or_cmd():
    """
    Writing >64 KiB (256 KiB) to stderr during startup and during a command with
    ret_stderr=False must not deadlock the pipe; stderr must also be isolated per command.
    """
    script = (
        "import sys\n"
        "sys.stderr.buffer.write(b'W' * 262144 + b'\\n')\n"
        "sys.stderr.buffer.flush()\n"
        "sys.stdout.buffer.write(b'\\x00')\n"
        "sys.stdout.buffer.flush()\n"
        "for line in sys.stdin.buffer:\n"
        "    cmd = line.strip()\n"
        "    if cmd == b'q':\n"
        "        sys.stdout.buffer.write(b'\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "        break\n"
        "    if cmd == b'noisy':\n"
        "        sys.stderr.buffer.write(b'E' * 262144 + b'TAIL_NOISE\\n')\n"
        "        sys.stderr.buffer.flush()\n"
        "        sys.stdout.buffer.write(b'done\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
        "    elif cmd == b'clean':\n"
        "        sys.stderr.buffer.write(b'CLEAN_ERR\\n')\n"
        "        sys.stderr.buffer.flush()\n"
        "        sys.stdout.buffer.write(b'ok\\x00')\n"
        "        sys.stdout.buffer.flush()\n"
    )
    real_popen = subprocess.Popen

    def fake_popen(cmd, **kwargs):
        return real_popen([sys.executable, "-c", script], **kwargs)

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with open_sync.open("dummy") as rz:
            assert len(rz.last_stderr) <= open_sync.open._MAX_STDERR_BYTES
            assert rz.cmd("noisy") == "done"
            assert "TAIL_NOISE" in rz.last_stderr
            assert len(rz.last_stderr) <= open_sync.open._MAX_STDERR_BYTES

            out = rz.cmd("clean", ret_stderr=True)
            assert "CLEAN_ERR" in out
            assert "TAIL_NOISE" not in out


def test_open_startup_eof_with_large_stderr_does_not_deadlock():
    """
    Child closing stdout early and then emitting >64 KiB to stderr before exiting must
    drain without deadlocking and include the bounded stderr tail in BrokenPipeError.
    """
    spawned = []
    real_popen = subprocess.Popen
    script = (
        "import os, sys\n"
        "os.close(1)\n"
        "sys.stderr.buffer.write(b'X' * 262144 + b'FATAL_TAIL\\n')\n"
        "sys.stderr.buffer.flush()\n"
        "sys.exit(3)\n"
    )

    def fake_popen(cmd, **kwargs):
        proc = real_popen([sys.executable, "-c", script], **kwargs)
        spawned.append(proc)
        return proc

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with pytest.raises(BrokenPipeError, match=r"exit code 3.*FATAL_TAIL"):
            open_sync.open("dummy")

    assert len(spawned) == 1
    proc = spawned[0]
    assert proc.poll() == 3
    assert proc.stdin.closed
    assert proc.stdout.closed
    assert proc.stderr.closed


def test_open_with_stderr_devnull():
    """
    Passing stderr=subprocess.DEVNULL leaves process.stderr as None and must work cleanly.
    """
    script = (
        "import sys\n"
        "sys.stdout.buffer.write(b'\\x00')\n"
        "sys.stdout.buffer.flush()\n"
        "for line in sys.stdin.buffer:\n"
        "    cmd = line.strip()\n"
        "    sys.stdout.buffer.write(b'ok\\x00')\n"
        "    sys.stdout.buffer.flush()\n"
        "    if cmd == b'q':\n"
        "        break\n"
    )
    real_popen = subprocess.Popen

    def fake_popen(cmd, **kwargs):
        return real_popen([sys.executable, "-c", script], **kwargs)

    with patch.object(open_sync, "Popen", side_effect=fake_popen):
        with open_sync.open("dummy", stderr=subprocess.DEVNULL) as rz:
            assert rz.process.stderr is None
            assert rz.cmd("i") == "ok"
            assert rz.cmd("i", ret_stderr=True) == "ok"
            assert rz.last_stderr == ""
