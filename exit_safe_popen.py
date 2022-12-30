from contextlib import suppress
from subprocess import Popen, PIPE, list2cmdline, STARTUPINFO, Handle
import _winapi
from win32api import OpenProcess, OpenThread, CloseHandle
from win32con import PROCESS_TERMINATE, PROCESS_SET_QUOTA, THREAD_SUSPEND_RESUME
from win32job import CreateJobObject, QueryInformationJobObject, \
    JobObjectExtendedLimitInformation, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, \
    AssignProcessToJobObject, SetInformationJobObject, TerminateJobObject
from win32process import CREATE_SUSPENDED, ResumeThread
from os import name, PathLike, fsdecode, environ
from warnings import warn 
from sys import audit

class ExitSafePopen(Popen):
    """
    Associates a JobObject with a Python subprocess to safely handle orphaned child processes.
    Inherits from the built-in class 'Popen'

    Arguments:
      args: A string, or a sequence of program arguments.

      bufsize: supplied as the buffering argument to the open() function when
          creating the stdin/stdout/stderr pipe file objects

      executable: A replacement program to execute.

      stdin, stdout and stderr: These specify the executed programs' standard
          input, standard output and standard error file handles, respectively.

      preexec_fn: (POSIX only) An object to be called in the child process
          just before the child is executed.

      close_fds: Controls closing or inheriting of file descriptors.

      shell: If true, the command will be executed through the shell.

      cwd: Sets the current directory before the child is executed.

      env: Defines the environment variables for the new process.

      text: If true, decode stdin, stdout and stderr using the given encoding
          (if set) or the system default otherwise.

      universal_newlines: Alias of text, provided for backwards compatibility.

      startupinfo and creationflags (Windows only)

      restore_signals (POSIX only)

      start_new_session (POSIX only)

      group (POSIX only)

      extra_groups (POSIX only)

      user (POSIX only)

      umask (POSIX only)

      pass_fds (POSIX only)

      encoding and errors: Text mode encoding and error handling to use for
          file objects stdin, stdout and stderr.

    Attributes:
        stdin, stdout, stderr, pid, tid, returncode
    """

    def __init__(self):
        self._permissions = PROCESS_TERMINATE | PROCESS_SET_QUOTA
        self._job_handle = None
        self._is_win = self._is_windows()
        if self._is_win:
            self._job_handle = self._init_job_object()
            if not self._is_win:
                print(self._job_handle)
        self._child = None
        self._process_handle = None
        self._original_execute_child = Popen._execute_child
        self._popen_exit = Popen.__exit__

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, traceback):
        # Calls subprocess.Popen's version of __exit__ to cleanup open PIPEs and to wait for the process.
        # Cleans up the monkeypatch and JobObject.
        with suppress(AttributeError):
            self._popen_exit(self, exc_type, exc_val, traceback)
            Popen._execute_child = self._original_execute_child
            if self._is_win and self._job_handle and self._process_handle:
                # Terminates the JobObject when we're done with it. JobObjects also terminate when the parent closes.
                TerminateJobObject(self._job_handle, int(self._process_handle))

    def _init_job_object(self):
        """Sets up a JobObject to pair with the spawned process."""
        # JobObject information retrieved from Nathaniel J. Smith
        # https://stackoverflow.com/a/23587108/10671703

        error = ""

        # Creates an empty Windows JobObject handle
        job_handle = CreateJobObject(None, "")
        # Returns None if CreateJobObject fails
        if not job_handle:
            self._is_win = False
            error = "Error: Could not create Windows JobObject"
            return error
        # Queries JobObject information so we can set LimitFlags which will
        # terminate all processes associated with the job when the job handle is closed
        extended_info = QueryInformationJobObject(job_handle, JobObjectExtendedLimitInformation)
        if extended_info == 0:
            self._is_win = False
            error = f"Error: Could not query JobObject {job_handle}"
            return error
        try:
            extended_info['BasicLimitInformation']['LimitFlags'] |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        except KeyError:
            self._is_win = False
            error = "Error: extended_info did not contain 'BasicLimitInformation' and/or 'LimitFlags'"
            return error
        info_set = SetInformationJobObject(job_handle, JobObjectExtendedLimitInformation, extended_info)
        if info_set == 0:
            self._is_win = False
            error = f"Error: extended_info could not be set to JobObject {job_handle}"
            return error
        return job_handle

    def _is_windows(self):
        is_windows = False
        if 'nt' in name:
            is_windows = True
        return is_windows

    def Popen(self, command, **kwargs):
        """Wrapper for subprocess.Popen that will setup a Windows JobObject to handle orphaned child processes."""
        if self._is_win:
            Popen._execute_child = _execute_child
            # Creates and runs child process
            super().__init__(command, **kwargs, creationflags=CREATE_SUSPENDED)
            Popen._execute_child = self._original_execute_child
            # Opens the process with the Windows api to get the process' handle
            with suppress(Exception):
                self._process_handle = OpenProcess(self._permissions, False, self.pid)
                AssignProcessToJobObject(self._job_handle, self._process_handle)
                thread_handle = OpenThread(THREAD_SUSPEND_RESUME, True, self.tid)
                ResumeThread(thread_handle)
                CloseHandle(thread_handle)
        else:
            super().__init__(command, **kwargs)


def _execute_child(self, args, executable, preexec_fn, close_fds,
                           pass_fds, cwd, env,
                           startupinfo, creationflags, shell,
                           p2cread, p2cwrite,
                           c2pread, c2pwrite,
                           errread, errwrite,
                           unused_restore_signals,
                           unused_gid, unused_gids, unused_uid,
                           unused_umask,
                           unused_start_new_session):
            """
            Used to monkeypatch a custom implementation of subprocess.Popen's execute program (MS Windows version)
            that adds tid as an attribute (Used to resume the process' halted thread)
            """

            assert not pass_fds, "pass_fds not supported on Windows."

            if isinstance(args, str):
                pass
            elif isinstance(args, bytes):
                if shell:
                    raise TypeError('bytes args is not allowed on Windows')
                args = list2cmdline([args])
            elif isinstance(args, PathLike):
                if shell:
                    raise TypeError('path-like args is not allowed when '
                                    'shell is true')
                args = list2cmdline([args])
            else:
                args = list2cmdline(args)

            if executable is not None:
                executable = fsdecode(executable)

            # Process startup details
            if startupinfo is None:
                startupinfo = STARTUPINFO()
            else:
                # bpo-34044: Copy STARTUPINFO since it is modified above,
                # so the caller can reuse it multiple times.
                startupinfo = startupinfo.copy()

            use_std_handles = -1 not in (p2cread, c2pwrite, errwrite)
            if use_std_handles:
                startupinfo.dwFlags |= _winapi.STARTF_USESTDHANDLES
                startupinfo.hStdInput = p2cread
                startupinfo.hStdOutput = c2pwrite
                startupinfo.hStdError = errwrite

            attribute_list = startupinfo.lpAttributeList
            have_handle_list = bool(attribute_list and
                                    "handle_list" in attribute_list and
                                    attribute_list["handle_list"])

            # If we were given an handle_list or need to create one
            if have_handle_list or (use_std_handles and close_fds):
                if attribute_list is None:
                    attribute_list = startupinfo.lpAttributeList = {}
                handle_list = attribute_list["handle_list"] = \
                    list(attribute_list.get("handle_list", []))

                if use_std_handles:
                    handle_list += [int(p2cread), int(c2pwrite), int(errwrite)]

                handle_list[:] = self._filter_handle_list(handle_list)

                if handle_list:
                    if not close_fds:
                        warn("startupinfo.lpAttributeList['handle_list'] "
                                      "overriding close_fds", RuntimeWarning)

                    # When using the handle_list we always request to inherit
                    # handles but the only handles that will be inherited are
                    # the ones in the handle_list
                    close_fds = False

            if shell:
                startupinfo.dwFlags |= _winapi.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = _winapi.SW_HIDE
                comspec = environ.get("COMSPEC", "cmd.exe")
                args = '{} /c "{}"'.format (comspec, args)

            if cwd is not None:
                cwd = fsdecode(cwd)

            audit("subprocess.Popen", executable, args, cwd, env)

            # Start the process
            try:
                hp, ht, pid, tid = _winapi.CreateProcess(executable, args,
                                         # no special security
                                         None, None,
                                         int(not close_fds),
                                         creationflags,
                                         env,
                                         cwd,
                                         startupinfo)
            finally:
                # Child is launched. Close the parent's copy of those pipe
                # handles that only the child should have open.  You need
                # to make sure that no handles to the write end of the
                # output pipe are maintained in this process or else the
                # pipe will not close when the child process exits and the
                # ReadFile will hang.
                self._close_pipe_fds(p2cread, p2cwrite,
                                     c2pread, c2pwrite,
                                     errread, errwrite)

            # Retain the process handle, but close the thread handle
            self._child_created = True
            self._handle = Handle(hp)
            self.pid = pid
            self.tid = tid
            _winapi.CloseHandle(ht)
