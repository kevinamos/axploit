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

import aiohttp
import os
import shutil
import asyncio

from uuid import UUID, uuid4
from .port_manager import PortManager
from ..config import Config
from ..utils.asyncio import wait_run_in_executor

import logging
log = logging.getLogger(__name__)


class Project:

    """
    A project contains a list of VM.
    In theory VM are isolated project/project.

    :param project_id: force project identifier (None by default auto generate an UUID)
    :param path: path of the project. (None use the standard directory)
    :param location: parent path of the project. (None should create a tmp directory)
    :param temporary: boolean to tell if the project is a temporary project (destroy when closed)
    """

    def __init__(self, name=None, project_id=None, path=None, location=None, temporary=False):

        self._name = name
        if project_id is None:
            self._id = str(uuid4())
        else:
            try:
                UUID(project_id, version=4)
            except ValueError:
                raise aiohttp.web.HTTPBadRequest(text="{} is not a valid UUID".format(project_id))
            self._id = project_id

        self._location = None
        if location is None:
            self._location = self._config().get("project_directory", self._get_default_project_directory())
        else:
            self.location = location

        self._vms = set()
        self._vms_to_destroy = set()
        self.temporary = temporary
        self._used_tcp_ports = set()
        self._used_udp_ports = set()

        if path is None:
            path = os.path.join(self._location, self._id)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            raise aiohttp.web.HTTPInternalServerError(text="Could not create project directory: {}".format(e))
        self.path = path

        log.info("Project {id} with path '{path}' created".format(path=self._path, id=self._id))

    def __json__(self):

        return {
            "name": self._name,
            "project_id": self._id,
            "location": self._location,
            "temporary": self._temporary,
            "path": self._path,
        }

    def _config(self):

        return Config.instance().get_section_config("Server")

    def is_local(self):

        return self._config().getboolean("local", False)

    @classmethod
    def _get_default_project_directory(cls):
        """
        Return the default location for the project directory
        depending of the operating system
        """

        server_config = Config.instance().get_section_config("Server")
        path = os.path.expanduser(server_config.get("projects_path", "~/GNS3/projects"))
        path = os.path.normpath(path)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            raise aiohttp.web.HTTPInternalServerError(text="Could not create project directory: {}".format(e))
        return path

    @property
    def id(self):

        return self._id

    @property
    def location(self):

        return self._location

    @location.setter
    def location(self, location):

        if location != self._location and self.is_local() is False:
            raise aiohttp.web.HTTPForbidden(text="You are not allowed to modify the project directory location")

        self._location = location

    @property
    def path(self):

        return self._path

    @path.setter
    def path(self, path):

        if hasattr(self, "_path"):
            if path != self._path and self.is_local() is False:
                raise aiohttp.web.HTTPForbidden(text="You are not allowed to modify the project directory location")

        old_path = None
        if hasattr(self, "_path"):
            old_path = self._path

        self._path = path
        self._update_temporary_file()

    @asyncio.coroutine
    def clean_old_path(self, old_path):
        """
        Called after a project location change. All the modules should
        have been notified before
        """
        if self._temporary:
            try:
                yield from wait_run_in_executor(shutil.rmtree, old_path)
            except OSError as e:
                log.warn("Can't remove temporary directory {}: {}".format(old_path, e))

    @property
    def name(self):

        return self._name

    @name.setter
    def name(self, name):

        self._name = name

    @property
    def vms(self):

        return self._vms

    @property
    def temporary(self):

        return self._temporary

    @temporary.setter
    def temporary(self, temporary):

        if hasattr(self, 'temporary') and temporary == self._temporary:
            return

        self._temporary = temporary
        self._update_temporary_file()

    def record_tcp_port(self, port):
        """
        Associate a reserved TCP port number with this project.

        :param port: TCP port number
        """

        if port not in self._used_tcp_ports:
            self._used_tcp_ports.add(port)

    def record_udp_port(self, port):
        """
        Associate a reserved UDP port number with this project.

        :param port: UDP port number
        """

        if port not in self._used_udp_ports:
            self._used_udp_ports.add(port)

    def remove_tcp_port(self, port):
        """
        Removes an associated TCP port number from this project.

        :param port: TCP port number
        """

        if port in self._used_tcp_ports:
            self._used_tcp_ports.remove(port)

    def remove_udp_port(self, port):
        """
        Removes an associated UDP port number from this project.

        :param port: UDP port number
        """

        if port in self._used_udp_ports:
            self._used_udp_ports.remove(port)

    def _update_temporary_file(self):
        """
        Update the .gns3_temporary file in order to reflect current
        project status.
        """

        if not hasattr(self, "_path"):
            return

        if self._temporary:
            try:
                with open(os.path.join(self._path, ".gns3_temporary"), 'w+') as f:
                    f.write("1")
            except OSError as e:
                raise aiohttp.web.HTTPInternalServerError(text="Could not create temporary project: {}".format(e))
        else:
            if os.path.exists(os.path.join(self._path, ".gns3_temporary")):
                try:
                    os.remove(os.path.join(self._path, ".gns3_temporary"))
                except OSError as e:
                    raise aiohttp.web.HTTPInternalServerError(text="Could not mark project as no longer temporary: {}".format(e))

    def module_working_directory(self, module_name):
        """
        Returns a working directory for the module
        If the directory doesn't exist, the directory is created.

        :param module_name: name for the module
        :returns: working directory
        """

        workdir = self.module_working_path(module_name)
        try:
            os.makedirs(workdir, exist_ok=True)
        except OSError as e:
            raise aiohttp.web.HTTPInternalServerError(text="Could not create module working directory: {}".format(e))
        return workdir

    def module_working_path(self, module_name):
        """
        Returns the working directory for the module. If you want
        to be sure to have the directory on disk take a look on:
            module_working_directory
        """

        return os.path.join(self._path, "project-files", module_name)

    def vm_working_directory(self, vm):
        """
        Returns a working directory for a specific VM.
        If the directory doesn't exist, the directory is created.

        :param vm: VM instance

        :returns: VM working directory
        """

        workdir = os.path.join(self._path, "project-files", vm.manager.module_name.lower(), vm.id)
        try:
            os.makedirs(workdir, exist_ok=True)
        except OSError as e:
            raise aiohttp.web.HTTPInternalServerError(text="Could not create the VM working directory: {}".format(e))
        return workdir

    def capture_working_directory(self):
        """
        Returns a working directory where to store packet capture files.

        :returns: path to the directory
        """

        workdir = os.path.join(self._path, "project-files", "captures")
        try:
            os.makedirs(workdir, exist_ok=True)
        except OSError as e:
            raise aiohttp.web.HTTPInternalServerError(text="Could not create the capture working directory: {}".format(e))
        return workdir

    def mark_vm_for_destruction(self, vm):
        """
        :param vm: An instance of VM
        """

        self.remove_vm(vm)
        self._vms_to_destroy.add(vm)

    def add_vm(self, vm):
        """
        Adds a VM to the project.
        In theory this should be called by the VM manager.

        :param vm: VM instance
        """

        self._vms.add(vm)

    def remove_vm(self, vm):
        """
        Removes a VM from the project.
        In theory this should be called by the VM manager.

        :param vm: VM instance
        """

        if vm in self._vms:
            self._vms.remove(vm)

    @asyncio.coroutine
    def close(self):
        """
        Closes the project, but keep information on disk
        """

        for module in self.modules():
            yield from module.instance().project_closing(self)
        yield from self._close_and_clean(self._temporary)
        for module in self.modules():
            yield from module.instance().project_closed(self)

    @asyncio.coroutine
    def _close_and_clean(self, cleanup):
        """
        Closes the project, and cleanup the disk if cleanup is True

        :param cleanup: If True drop the project directory
        """

        tasks = []
        for vm in self._vms:
            tasks.append(asyncio.async(vm.manager.close_vm(vm.id)))

        if tasks:
            done, _ = yield from asyncio.wait(tasks)
            for future in done:
                try:
                    future.result()
                except (Exception, GeneratorExit) as e:
                    log.error("Could not close VM or device {}".format(e), exc_info=1)

        if cleanup and os.path.exists(self.path):
            try:
                yield from wait_run_in_executor(shutil.rmtree, self.path)
                log.info("Project {id} with path '{path}' deleted".format(path=self._path, id=self._id))
            except OSError as e:
                raise aiohttp.web.HTTPInternalServerError(text="Could not delete the project directory: {}".format(e))
        else:
            log.info("Project {id} with path '{path}' closed".format(path=self._path, id=self._id))

        if self._used_tcp_ports:
            log.warning("Project {} has TCP ports still in use: {}".format(self.id, self._used_tcp_ports))
        if self._used_udp_ports:
            log.warning("Project {} has UDP ports still in use: {}".format(self.id, self._used_udp_ports))

        # clean the remaining ports that have not been cleaned by their respective VM or device.
        port_manager = PortManager.instance()
        for port in self._used_tcp_ports.copy():
            port_manager.release_tcp_port(port, self)
        for port in self._used_udp_ports.copy():
            port_manager.release_udp_port(port, self)

    @asyncio.coroutine
    def commit(self):
        """
        Writes project changes on disk
        """

        while self._vms_to_destroy:
            vm = self._vms_to_destroy.pop()
            yield from vm.delete()
            self.remove_vm(vm)
        for module in self.modules():
            yield from module.instance().project_committed(self)

    @asyncio.coroutine
    def delete(self):
        """
        Removes project from disk
        """

        for module in self.modules():
            yield from module.instance().project_closing(self)
        yield from self._close_and_clean(True)
        for module in self.modules():
            yield from module.instance().project_closed(self)

    @classmethod
    def clean_project_directory(cls):
        """
        At startup drop old temporary project. After a crash for example
        """

        config = Config.instance().get_section_config("Server")
        directory = config.get("project_directory", cls._get_default_project_directory())
        if os.path.exists(directory):
            for project in os.listdir(directory):
                path = os.path.join(directory, project)
                if os.path.exists(os.path.join(path, ".gns3_temporary")):
                    log.warning("Purge old temporary project {}".format(project))
                    shutil.rmtree(path)

    def modules(self):
        """
        Returns all loaded VM modules.
        """

        # We import it at the last time to avoid circular dependencies
        from ..modules import MODULES
        return MODULES
