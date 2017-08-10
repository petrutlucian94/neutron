# Copyright 2017 Cloudbase Solutions.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import random
import time

import eventlet
from eventlet import tpool
from ovs import winutils as ovs_winutils
from os_win import utilsfactory
from os_win.utils.io import ioutils

import win32con
import win32event
import win32process
import win32security


def avoid_blocking_call(f, *args, **kwargs):
    """Ensure that the method "f" will not block other greenthreads.

    Performs the call to the function "f" received as parameter in a
    different thread using tpool.execute when called from a greenthread.
    This will ensure that the function "f" will not block other greenthreads.
    If not called from a greenthread, it will invoke the function "f" directly.
    The function "f" will receive as parameters the arguments "args" and
    keyword arguments "kwargs".
    """
    # Note that eventlet.getcurrent will always return a greenlet object.
    # In case of a greenthread, the parent greenlet will always be the hub
    # loop greenlet.
    if eventlet.getcurrent().parent:
        return tpool.execute(f, *args, **kwargs)
    else:
        return f(*args, **kwargs)


class WindowsException(Exception):
    """Base Windows Exception

    This class is inherited by all the other exceptions that are used in
    this file. The 'error_message' property should be defined in the class
    that inherits from this with a particular message if needed.
    """
    error_message = None

    def __init__(self, message):
        super(WindowsException, self).__init__()
        # The error message which will be printed for this exception
        self.error_message = message

    def __str__(self):
        return self.error_message


class NamedPipeException(WindowsException):
    """Exception raised when there is an error with the named pipes.

    If there is an error code associated with this exception, it can be
    retrieved by accessing the 'code' property of this class.
    """
    def __init__(self, message, error_code=None):
        super(NamedPipeException, self).__init__(message)
        # The error code associated with this exception. This property should
        # be different than 'None' if there is an existing error code.
        self.code = error_code
        if self.code:
            # Appending the error code to the message
            self.error_message += " Error code: '%s'." % self.code

    def __str__(self):
        return self._error_string


class ProcessException(WindowsException):
    """Exception raised when there is an error with the child process.

    This class inherits the implementation from the super class, it does not
    have anything particular. It is intentionally left blank.
    """
    pass


class NamedPipe(object):
    def __init__(self, pipe_name=None, sec_attributes=-1):
        """Create a named pipe with the given name.

        :param pipe_name(Optional): string representing the name of the pipe
            which should be used to create the named pipe
        :param sec_attributes(Optional): type win32security.SECURITY_ATTRIBUTES
            The default value is -1 which uses the default security attributes.
            This means that the named pipe handle is inherited when a new
            process is created.
        """
        if pipe_name is None:
            # Generate a random name for the named pipe if the name was not
            # passed explicitly as parameter.
            pipe_name = ("NamedPipe_%d_%s" %
                         (time.time(), str(random.random()).split(".")[1]))

        # Creating the name for a local named pipe. The property "name" will
        # have "\\.\pipe\" appended at the start of pipe_name
        self.name = ovs_winutils.get_pipe_name(pipe_name)
        # This property will contain the handle of the named pipe which can
        # be accessed later on.
        self.namedpipe = ovs_winutils.create_named_pipe(self.name,
                                                        saAttr=sec_attributes)

        if not self.namedpipe:
            # If there was an error when creating the named pipe, the property
            # "namedpipe" should be None. We raise an exception in this case
            raise NamedPipeException("Failed to create named pipe.")

        conn_evt = eventlet.patcher.original('threading').Event()
        conn_evt.set()
        self._input_queue = ioutils.IOQueue(conn_evt)
        self._output_queue = ioutils.IOQueue(conn_evt)

        self._handler = utilsfactory.get_named_pipe_handler(
            pipe_handle=self.namedpipe.handle,
            input_queue=self._input_queue,
            output_queue=self._output_queue,
            connect_event=conn_evt)

    def connect(self):
        ovs_winutils.connect_named_pipe(self.namedpipe)
        self._handler.start()

    def wait(self, timeout=win32event.INFINITE):
        """Wait until there is something to read from the named pipe or the

        timeout passed as parameter has passed.

        :param timeout: int representing the timeout in milliseconds
        """
        avoid_blocking_call(self._handler._stopped.wait)

    def write(self, data, blocking=False):
        if blocking:
            avoid_blocking_call(self._handler.blocking_write, data)
        else:
            avoid_blocking_call(self._input_queue.put, data)

    def _read(self):
        data = ''
        while not self._output_queue.empty():
            data += self._output_queue.get()
        return data

    def read(self):
        return avoid_blocking_call(self._read)

    def create_file(self, sec_attributes=-1):
        """Create the file for the named pipe and store it in the '_npipe_file'

        property of the class.

        :param sec_attributes: type win32security.SECURITY_ATTRIBUTES
            The default value is -1 which uses the default security attributes.
            This means that the file handle will NOT be inherited when
            a new process is created.
        """
        try:
            # Create the file using the name of the named pipe with the given
            # security attributes
            self._npipe_file = ovs_winutils.create_file(
                self.name, attributes=sec_attributes)
            try:
                ovs_winutils.set_pipe_mode(
                    self._npipe_file,
                    ovs_winutils.win32pipe.PIPE_READMODE_BYTE)
            except ovs_winutils.pywintypes.error as e:
                raise NamedPipeException(
                    "Could not set pipe read mode to byte. "
                    "Error: %s." % e.strerror, e.winerror)
        except ovs_winutils.pywintypes.error as e:
            raise NamedPipeException("Could not create file for named pipe. "
                                     "Error: %s." % e.strerror, e.winerror)

    def close_filehandle(self):
        """Close the file handle."""
        ovs_winutils.close_handle(self._npipe_file)

    def get_file_handle(self):
        """Returns the file handle."""
        return self._npipe_file

    def close_all_handles(self):
        """Close all the handles used by this class."""
        if hasattr(self, "namedpipe") and self.namedpipe:
            ovs_winutils.close_handle(self.namedpipe)
        if hasattr(self, "_npipe_file") and self._npipe_file:
            ovs_winutils.close_handle(self._npipe_file)

    def __del__(self):
        """Make sure all the handles are closed."""
        self.close_all_handles()


class ProcessWithNamedPipes(object):
    class HandleClass(object):
        """This class is used only to provide a 'close' method for the stdin,
        stdout and stderr of the new process. This ensures compatibility with
        the subprocess.Popen returned object.
        """
        def __init__(self, namedpipe):
            self.namedpipe = namedpipe

        def close(self):
            # Close all the handles used
            if self.namedpipe:
                self.namedpipe.close_all_handles()
                self.namedpipe = None

    # The maximum number of bytes to be read
    _BUFSIZE = 16384

    def __init__(self, cmd, env):
        """Create a new process executing 'cmd' and with environment 'env'.

        :param cmd: string representing the command line to be executed
        :param env: instance representing the environment which should be used
            for the new process. Look at 'os.environ' for an example.
        """
        # The startupinfo structure used to spawn the new process
        self._si = win32process.STARTUPINFO()

        # Attributes defined to ensure compatibility with the subprocess.Popen
        # returned object.
        self.returncode = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.pid = None

        # Convert the command to be a single string
        cmd = " ".join(cmd)
        # Initialize the named pipes used for stdin, stdout and stderr
        self._initialize_named_pipes_for_std()
        # Create the child process
        self._start_process(cmd, env)

    def _initialize_named_pipes_for_std(self):
        """Initialize the named pipes used for communication with the child
        process.
        """

        # used in generating the name for the pipe
        pid = os.getpid()

        # Security attributes for the named pipes, should not be inherited
        # by the child process. Those are used by the parent process to
        # communicate with the child process.
        _saAttr_pipe = win32security.SECURITY_ATTRIBUTES()
        _saAttr_pipe.bInheritHandle = 0
        # Security attributes for the file handles, they should be inherited
        # by the child process which will use them as stdin, stdout and stderr.
        # The parent process will close those handles after the child process
        # is created.
        _saAttr_file = win32security.SECURITY_ATTRIBUTES()
        _saAttr_file.bInheritHandle = 1

        def create_namedpipe_and_file(prefix, saAttr_pipe=_saAttr_pipe,
                                      saAttr_file=_saAttr_file):
            """Create the named pipe and the file for it.

            :param prefix: string representing the prefix which will be
                appended to the start of the name for the pipe
            :param saAttr_pipe: security attributes used to create
                the named pipe
            :param saAttr_file: security attributes used to create the file
            """
            pipename = ("%s_NamedPipe_%d_%d_%s" % (
                prefix, pid, time.time(), str(random.random()).split(".")[1]))
            # Create the named pipe
            pipe = NamedPipe(pipe_name=pipename,
                             sec_attributes=saAttr_pipe)
            # Create the file for the previously created named pipe
            pipe.create_file(sec_attributes=saAttr_file)
            return pipe

        # Create the named pipes and the files used for parent - child process
        # communication.
        _pipe_stdin = create_namedpipe_and_file("Stdin")
        self._pipe_stdout = create_namedpipe_and_file("Stdout")
        self._pipe_stderr = create_namedpipe_and_file("Stderr")

        # Set the file handles from the named pipes as stdin, stdout and stderr
        # in startupinfo structure for the child process.
        self._si.hStdInput = _pipe_stdin.get_file_handle()
        self._si.hStdOutput = self._pipe_stdout.get_file_handle()
        self._si.hStdError = self._pipe_stderr.get_file_handle()
        self._si.dwFlags |= win32con.STARTF_USESTDHANDLES

        # Wrapping around stdin in order to be able to call self.stdin.close()
        # to close the stdin.
        self.stdin = ProcessWithNamedPipes.HandleClass(_pipe_stdin)
        _pipe_stdin = None

    def communicate(self, input=None):
        """Return stdout and stderr of the child process.

        Interact with process: Send the 'input' argument to stdin.
        The function waits until the process terminates and reads from
        stdout and stderr.

        :param input: string representing the input which should be sent
            to the child process. If this value is None, then nothing is passed
            as stdin for the child process.
        """

        self.stdin.namedpipe.connect()
        self._pipe_stdout.connect()
        self._pipe_stderr.connect()

        if input:
            # If we received any input, write it to stdin then close the handle
            # to send EOF on stdin to the child process
            self._stdin_write(input, blocking=True)
            self.stdin.close()

        # Wait for the process to terminate
        self.wait()
        self._pipe_stdout.wait()
        self._pipe_stderr.wait()

        stdout = self._pipe_stdout.read()
        stderr = self._pipe_stderr.read()

        # Close all the handles since the child process is terminated
        # at this point.
        self._pipe_stdout.close_all_handles()
        self._pipe_stdout = None
        self._pipe_stderr.close_all_handles()
        self._pipe_stderr = None

        # Return a tuple containing stdout and stderr to ensure compatibility
        # with the subprocess module.
        return (stdout, stderr)

    def _stdin_write(self, input, blocking=False):
        """Send input to stdin for the child process."""
        if input:
            encoded_buf = ovs_winutils.get_encoded_buffer(input)
            self.stdin.namedpipe.write(encoded_buf, blocking=blocking)

    def _start_process(self, cmd_line, env):
        """Create a process with the command line 'cmd_line' and environment
        'env'. Stores the pid of the child process in the 'pid' attribute.
        """
        app_name = None
        # The command line to be executed.
        command_line = cmd_line
        process_attributes = None
        thread_attributes = None
        # Each inheritable handle in the calling process is
        # inherited by the new process.
        inherit_handles = 1
        # The new process has a new console, instead of inheriting
        # its parent's console
        creation_flags = win32process.CREATE_NO_WINDOW
        # Environment used for the new process.
        new_environment = env
        current_directory = None

        proc_args = (app_name,
                     command_line,
                     process_attributes,
                     thread_attributes,
                     inherit_handles,
                     creation_flags,
                     new_environment,
                     current_directory,
                     self._si)
        proc_handles = win32process.CreateProcess(*proc_args)

        # Close the handles that the parent is not going to use
        self._pipe_stdout.close_filehandle()
        self._pipe_stderr.close_filehandle()

        self._hProcess, self._hThread, self.pid, self._tid = proc_handles

    def wait(self, timeout=None):
        """Wait for the process to terminate or until timeout expires.

        Returns returncode attribute. If timeout is None, then the method
        will wait until the process terminates.

        :param timeout: int or float representing the timeout in seconds
        """
        if timeout is None:
            timeout_millis = win32event.INFINITE
        else:
            timeout_millis = int(timeout * 1000)

        if self.returncode is None:
            # If the 'returncode' attribute is not set, it means that we
            # have to wait for the child process to terminate and to return the
            # exit code of it.
            result = avoid_blocking_call(win32event.WaitForSingleObject,
                                         self._hProcess,
                                         timeout_millis)
            if result == win32event.WAIT_TIMEOUT:
                raise ProcessException("Timeout Exception.")
            self.returncode = win32process.GetExitCodeProcess(self._hProcess)
        # Return the exit code of the child process
        return self.returncode
