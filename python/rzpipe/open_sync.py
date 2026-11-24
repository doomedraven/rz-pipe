#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""open_sync.py
This script use code from old __init__.py open object

"""

import re
import select
import socket
import time
import os
from subprocess import Popen, PIPE, TimeoutExpired
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import quote
from .open_base import OpenBase


try:
    import fcntl
except ImportError:
    fcntl = None


class open(OpenBase):
    _MAX_STDERR_BYTES = 65536
    _MAX_STDERR_DRAIN_BYTES = 4 * 1024 * 1024
    _STARTUP_CLEANUP_TIMEOUT = 5.0

    def __init__(self, filename="", flags=None, rizin_home=None, **kwargs):
        stderr = kwargs.pop("stderr", PIPE)
        super(open, self).__init__(filename, flags, **kwargs)
        self.last_stderr = ""
        if flags is None:
            flags = []
        if filename.startswith("http://"):
            self._cmd = self._cmd_http
            self.uri = filename + "/cmd"
        elif filename.startswith("ccall://"):
            self._cmd = self._cmd_native
            self.uri = filename[7:]
        elif filename.startswith("tcp://"):
            r = re.match(r"tcp://(\d+\.\d+.\d+.\d+):(\d+)/?", filename)
            if not r:
                raise ValueError(
                    "You must provide the tcp address in this format:\n"
                    "tcp://xxx.xxx.xxx.xxx:yyyy"
                )
            self._cmd = self._cmd_tcp
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((r.group(1), int(r.group(2))))
        elif filename:
            self._cmd = self._cmd_process
            if rizin_home is not None:
                if not os.path.isdir(rizin_home):
                    raise Exception(
                        "`rizin_home` passed is invalid, leave it None or put a valid path to rizin folder"
                    )
                rze = os.path.join(rizin_home, "rizin")
            else:
                rze = "rizin"
            if os.name == "nt":
                # avoid errors on Windows when subprocess messes with name
                rze += ".exe"
            cmd = [rze, "-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]
            try:
                self.process = Popen(
                    cmd,
                    shell=False,
                    stdin=PIPE,
                    stdout=PIPE,
                    stderr=stderr,
                    bufsize=0,
                )
            except Exception:
                raise Exception("ERROR: Cannot find rizin in PATH")
            try:
                # make pipes non-blocking before startup wait so stderr can be drained concurrently
                fd = self.process.stdout.fileno()
                if not self.__make_non_blocking(fd):
                    raise Exception("ERROR: Cannot make stdout pipe non-blocking")
                if self.process.stderr is not None:
                    fd = self.process.stderr.fileno()
                    if not self.__make_non_blocking(fd):
                        raise Exception("ERROR: Cannot make stderr pipe non-blocking")
                # reads any startup banners and the initial \x00 while draining stderr
                self._wait_startup_ready()
            except BaseException:
                self._quit_process()
                raise

    @classmethod
    def _append_stderr_tail(cls, buf, chunk):
        buf.extend(chunk)
        if len(buf) > cls._MAX_STDERR_BYTES:
            del buf[: len(buf) - cls._MAX_STDERR_BYTES]

    @classmethod
    def _drain_stderr_nonblocking(cls, err, buf=None, max_drain=None):
        if err is None:
            return True
        if max_drain is None:
            max_drain = cls._MAX_STDERR_DRAIN_BYTES
        eof = False
        drained = 0
        while drained < max_drain:
            try:
                chunk = err.read(65536)
            except OSError:
                break
            if chunk == b"":
                eof = True
                break
            if not chunk or not isinstance(chunk, bytes):
                break
            drained += len(chunk)
            if buf is not None:
                cls._append_stderr_tail(buf, chunk)
        return eof

    def _wait_startup_ready(self):
        stdo = self.process.stdout
        err = self.process.stderr
        stdo_fd = self._get_selectable_fd(stdo)
        err_fd = self._get_selectable_fd(err)
        err_eof = err is None
        err_tail = bytearray()
        poller = None
        if stdo_fd is not None and hasattr(select, "poll"):
            poller = select.poll()
            poller.register(stdo_fd, select.POLLIN)
            if err_fd is not None:
                poller.register(err_fd, select.POLLIN)

        while True:
            got_data = False
            if err is not None and not err_eof:
                err_chunk = None
                try:
                    err_chunk = err.read(65536)
                except BlockingIOError:
                    pass
                if err_chunk == b"":
                    err_eof = True
                    if poller is not None and err_fd is not None:
                        try:
                            poller.unregister(err_fd)
                        except KeyError:
                            pass
                elif err_chunk and isinstance(err_chunk, bytes):
                    got_data = True
                    self._append_stderr_tail(err_tail, err_chunk)

            chunk = None
            try:
                chunk = stdo.read(4096)
            except BlockingIOError:
                pass
            if chunk == b"":
                rc, stderr_data = self._cleanup_startup_process(err_tail)
                raise BrokenPipeError(
                    self._format_eof_error(
                        "ERROR: rizin exited before initializing pipe",
                        rc,
                        stderr_data,
                    )
                )
            if chunk:
                got_data = True
                if b"\x00" in chunk:
                    if not err_eof:
                        self._drain_stderr_nonblocking(err, err_tail)
                    self.last_stderr = (
                        bytes(err_tail).decode("utf-8", errors="ignore")
                        if err_tail
                        else ""
                    )
                    return

            if got_data:
                continue

            if poller is not None:
                try:
                    poller.poll(100)
                except InterruptedError:
                    pass
            elif stdo_fd is not None:
                rlist = [stdo_fd]
                if err_fd is not None and not err_eof:
                    rlist.append(err_fd)
                try:
                    select.select(rlist, [], [], 0.1)
                except (InterruptedError, ValueError):
                    time.sleep(0.01)
            else:
                time.sleep(0.01)

    @staticmethod
    def _format_eof_error(prefix, rc, stderr_bytes):
        msg = prefix
        if isinstance(rc, int):
            msg = f"{msg} (exit code {rc})"
        if isinstance(stderr_bytes, (bytes, bytearray)) and stderr_bytes:
            if len(stderr_bytes) > 4096:
                stderr_bytes = stderr_bytes[-4096:]
            err_msg = bytes(stderr_bytes).decode("utf-8", errors="ignore").strip()
            if err_msg:
                msg = f"{msg}: {err_msg}"
        return msg

    def _cleanup_startup_process(self, err_tail=None, timeout=None):
        proc = getattr(self, "process", None)
        if proc is None:
            return None, b""
        if timeout is None:
            timeout = self._STARTUP_CLEANUP_TIMEOUT
        buf = bytearray(err_tail) if err_tail else bytearray()
        try:
            if proc.stdin is not None and not proc.stdin.closed:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            deadline = time.monotonic() + timeout
            err_eof = proc.stderr is None
            err_fd = self._get_selectable_fd(proc.stderr)
            while True:
                if not err_eof:
                    err_eof = self._drain_stderr_nonblocking(proc.stderr, buf)
                if proc.poll() is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    proc.wait()
                    break
                if err_fd is not None and not err_eof:
                    try:
                        select.select([err_fd], [], [], min(0.05, remaining))
                    except (InterruptedError, ValueError, OSError):
                        time.sleep(min(0.01, remaining))
                else:
                    try:
                        proc.wait(timeout=min(0.05, remaining))
                    except TimeoutExpired:
                        pass
            if not err_eof:
                self._drain_stderr_nonblocking(proc.stderr, buf)
        except BaseException:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            raise
        finally:
            for f in (proc.stdin, proc.stdout, proc.stderr):
                if f is not None and not f.closed:
                    try:
                        f.close()
                    except OSError:
                        pass
            if hasattr(self, "process"):
                delattr(self, "process")
        return proc.returncode, bytes(buf)

    @staticmethod
    def __make_non_blocking(fd):
        if fcntl is not None:
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            return True

        if os.name != "nt":
            raise NotImplementedError()

        import msvcrt
        from ctypes import windll, byref
        from ctypes.wintypes import HANDLE, DWORD, BOOL

        try:
            from ctypes import POINTER
        except:
            from ctypes.wintypes import POINTER

        LPDWORD = POINTER(DWORD)
        SetNamedPipeHandleState = windll.kernel32.SetNamedPipeHandleState
        SetNamedPipeHandleState.argtypes = [HANDLE, LPDWORD, LPDWORD, LPDWORD]
        SetNamedPipeHandleState.restype = BOOL

        h = msvcrt.get_osfhandle(fd)

        PIPE_NOWAIT = DWORD(0x00000001)
        res = SetNamedPipeHandleState(h, byref(PIPE_NOWAIT), None, None)
        return res != 0

    @staticmethod
    def _get_selectable_fd(stream):
        if os.name == "nt" or stream is None:
            return None
        try:
            fd = stream.fileno()
        except (AttributeError, OSError, ValueError):
            return None
        if isinstance(fd, int) and fd >= 0:
            return fd
        return None

    def _raise_cmd_eof(self, err, err_tail=None):
        buf = bytearray(err_tail) if err_tail else bytearray()
        self._drain_stderr_nonblocking(err, buf)
        rc = self.process.poll()
        if rc is None:
            try:
                rc = self.process.wait(timeout=0.05)
            except (TimeoutExpired, OSError, TypeError):
                pass
            self._drain_stderr_nonblocking(err, buf)
        self.last_stderr = bytes(buf).decode("utf-8", errors="ignore") if buf else ""
        raise BrokenPipeError(
            self._format_eof_error(
                "ERROR: rizin process closed stdout unexpectedly",
                rc,
                buf,
            )
        )

    def _cmd_process(self, cmd, **kwargs):
        if not hasattr(self, "process") or self.process is None:
            raise BrokenPipeError("ERROR: rizin process is not running")
        if not self.process.stdin:
            raise ValueError("self.process.stdin is None")

        if kwargs.get("echo_cmd"):
            print(f"\rrz exec: '{cmd}'")
        cmd = cmd.strip().replace("\n", ";")
        self.process.stdin.write((cmd + "\n").encode("utf8"))
        self.process.stdin.flush()

        stdo = self.process.stdout
        err = self.process.stderr
        if not stdo:
            raise ValueError("self.process.stdout is None")

        read_size = 65536
        ret_stderr = bool(kwargs.get("ret_stderr"))
        stdo_fd = self._get_selectable_fd(stdo)
        err_fd = self._get_selectable_fd(err)
        err_eof = err is None
        err_tail = bytearray()
        poller = None
        if stdo_fd is not None and hasattr(select, "poll"):
            poller = select.poll()
            poller.register(stdo_fd, select.POLLIN)
            if err_fd is not None:
                poller.register(err_fd, select.POLLIN)

        chunks = []
        while True:
            got_data = False
            foo = None
            try:
                foo = stdo.read(read_size)
            except BlockingIOError:
                pass
            if foo == b"":
                self._raise_cmd_eof(err, err_tail)
            if foo:
                got_data = True
                idx = foo.find(b"\0")
                if idx != -1:
                    chunks.append(foo[:idx])
                    if err is not None and not err_eof:
                        extra = bytearray()
                        self._drain_stderr_nonblocking(err, extra)
                        if extra:
                            self._append_stderr_tail(err_tail, extra)
                            if ret_stderr:
                                chunks.append(bytes(extra))
                    break
                chunks.append(foo)

            if err is not None and not err_eof:
                err_chunk = None
                try:
                    err_chunk = err.read(read_size)
                except BlockingIOError:
                    pass
                if err_chunk == b"":
                    err_eof = True
                    if poller is not None and err_fd is not None:
                        try:
                            poller.unregister(err_fd)
                        except KeyError:
                            pass
                elif err_chunk and isinstance(err_chunk, bytes):
                    got_data = True
                    self._append_stderr_tail(err_tail, err_chunk)
                    if ret_stderr:
                        chunks.append(err_chunk)

            if got_data:
                continue

            if poller is not None:
                try:
                    poller.poll(100)
                except InterruptedError:
                    pass
            elif stdo_fd is not None:
                rlist = [stdo_fd]
                if err_fd is not None and not err_eof:
                    rlist.append(err_fd)
                try:
                    select.select(rlist, [], [], 0.1)
                except (InterruptedError, ValueError):
                    time.sleep(0.01)
            else:
                time.sleep(0.01)

        self.last_stderr = (
            bytes(err_tail).decode("utf-8", errors="ignore") if err_tail else ""
        )
        return b"".join(chunks).decode("utf-8", errors="ignore")

    def _cmd_http(self, cmd):
        try:
            quoted_cmd = quote(cmd)
            response = urlopen("{uri}/{cmd}".format(uri=self.uri, cmd=quoted_cmd))
            return response.read().decode("utf-8", errors="ignore")
        except URLError:
            pass
        return None

    def _cmd_tcp(self, cmd):
        res = b""
        self.conn.sendall(str.encode(cmd, "utf-8"))
        data = self.conn.recv(512)
        while data:
            res += data
            data = self.conn.recv(512)
        return res.decode("utf-8", errors="ignore")
