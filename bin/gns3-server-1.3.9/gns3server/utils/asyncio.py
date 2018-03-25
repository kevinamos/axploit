# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 GNS3 Technologies Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import asyncio


@asyncio.coroutine
def wait_run_in_executor(func, *args):
    """
    Run blocking code in a different thread and wait
    for the result.

    :param func: Run this function in a different thread
    :param args: Parameters of the function
    :returns: Return the result of the function
    """

    loop = asyncio.get_event_loop()
    future = loop.run_in_executor(None, func, *args)
    yield from asyncio.wait([future])
    return future.result()


@asyncio.coroutine
def subprocess_check_output(*args, cwd=None, env=None):
    """
    Run a command and capture output

    :param *args: List of command arguments
    :param cwd: Current working directory
    :param env: Command environment
    :returns: Command output
    """

    proc = yield from asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, cwd=cwd, env=env)
    output = yield from proc.stdout.read()
    if output is None:
        return ""
    # If we received garbage we ignore invalid characters
    # it should happend only when user try to use another binary
    # and the code of VPCS, dynamips... Will detect it's not the correct binary
    return output.decode("utf-8", errors="ignore")


@asyncio.coroutine
def wait_for_process_termination(process, timeout=10):
    """
    Wait for a process terminate, and raise asyncio.TimeoutError in case of
    timeout.

    In theory this can be implemented by just:
    yield from asyncio.wait_for(self._iou_process.wait(), timeout=100)

    But it's broken before Python 3.4:
    http://bugs.python.org/issue23140

    :param process: An asyncio subprocess
    :param timeout: Timeout in seconds
    """

    while timeout > 0:
        if process.returncode is not None:
            return
        yield from asyncio.sleep(0.1)
        timeout -= 0.1
    raise asyncio.TimeoutError()
