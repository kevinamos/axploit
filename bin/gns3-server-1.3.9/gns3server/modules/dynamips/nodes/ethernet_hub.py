# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 GNS3 Technologies Inc.
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

"""
Hub object that uses the Bridge interface to create a hub with ports.
"""

import asyncio

from .bridge import Bridge
from ..nios.nio_udp import NIOUDP
from ..dynamips_error import DynamipsError

import logging
log = logging.getLogger(__name__)


class EthernetHub(Bridge):

    """
    Dynamips Ethernet hub (based on Bridge)

    :param name: name for this hub
    :param device_id: Device instance identifier
    :param project: Project instance
    :param manager: Parent VM Manager
    :param hypervisor: Dynamips hypervisor instance
    """

    def __init__(self, name, device_id, project, manager, hypervisor=None):

        super().__init__(name, device_id, project, manager, hypervisor)
        self._mappings = {}

    def __json__(self):

        return {"name": self.name,
                "device_id": self.id,
                "project_id": self.project.id}

    @asyncio.coroutine
    def create(self):

        yield from Bridge.create(self)
        log.info('Ethernet hub "{name}" [{id}] has been created'.format(name=self._name, id=self._id))

    @property
    def mappings(self):
        """
        Returns port mappings

        :returns: mappings list
        """

        return self._mappings

    @asyncio.coroutine
    def delete(self):
        """
        Deletes this hub.
        """

        for nio in self._nios:
            if nio and isinstance(nio, NIOUDP):
                self.manager.port_manager.release_udp_port(nio.lport, self._project)

        try:
            yield from Bridge.delete(self)
            log.info('Ethernet hub "{name}" [{id}] has been deleted'.format(name=self._name, id=self._id))
        except DynamipsError:
            log.debug("Could not properly delete Ethernet hub {}".format(self._name))
        if self._hypervisor and not self._hypervisor.devices:
            yield from self.hypervisor.stop()

    @asyncio.coroutine
    def add_nio(self, nio, port_number):
        """
        Adds a NIO as new port on this hub.

        :param nio: NIO instance to add
        :param port_number: port to allocate for the NIO
        """

        if port_number in self._mappings:
            raise DynamipsError("Port {} isn't free".format(port_number))

        yield from Bridge.add_nio(self, nio)

        log.info('Ethernet hub "{name}" [{id}]: NIO {nio} bound to port {port}'.format(name=self._name,
                                                                                       id=self._id,
                                                                                       nio=nio,
                                                                                       port=port_number))
        self._mappings[port_number] = nio

    @asyncio.coroutine
    def remove_nio(self, port_number):
        """
        Removes the specified NIO as member of this hub.

        :param port_number: allocated port number

        :returns: the NIO that was bound to the allocated port
        """

        if port_number not in self._mappings:
            raise DynamipsError("Port {} is not allocated".format(port_number))

        nio = self._mappings[port_number]
        if isinstance(nio, NIOUDP):
            self.manager.port_manager.release_udp_port(nio.lport, self._project)
        yield from Bridge.remove_nio(self, nio)

        log.info('Ethernet switch "{name}" [{id}]: NIO {nio} removed from port {port}'.format(name=self._name,
                                                                                              id=self._id,
                                                                                              nio=nio,
                                                                                              port=port_number))

        del self._mappings[port_number]
        return nio

    @asyncio.coroutine
    def start_capture(self, port_number, output_file, data_link_type="DLT_EN10MB"):
        """
        Starts a packet capture.

        :param port_number: allocated port number
        :param output_file: PCAP destination file for the capture
        :param data_link_type: PCAP data link type (DLT_*), default is DLT_EN10MB
        """

        if port_number not in self._mappings:
            raise DynamipsError("Port {} is not allocated".format(port_number))

        nio = self._mappings[port_number]

        data_link_type = data_link_type.lower()
        if data_link_type.startswith("dlt_"):
            data_link_type = data_link_type[4:]

        if nio.input_filter[0] is not None and nio.output_filter[0] is not None:
            raise DynamipsError("Port {} has already a filter applied".format(port_number))

        yield from nio.bind_filter("both", "capture")
        yield from nio.setup_filter("both", '{} "{}"'.format(data_link_type, output_file))

        log.info('Ethernet hub "{name}" [{id}]: starting packet capture on port {port}'.format(name=self._name,
                                                                                               id=self._id,
                                                                                               port=port_number))

    @asyncio.coroutine
    def stop_capture(self, port_number):
        """
        Stops a packet capture.

        :param port_number: allocated port number
        """

        if port_number not in self._mappings:
            raise DynamipsError("Port {} is not allocated".format(port_number))

        nio = self._mappings[port_number]
        yield from nio.unbind_filter("both")
        log.info('Ethernet hub "{name}" [{id}]: stopping packet capture on port {port}'.format(name=self._name,
                                                                                               id=self._id,
                                                                                               port=port_number))
