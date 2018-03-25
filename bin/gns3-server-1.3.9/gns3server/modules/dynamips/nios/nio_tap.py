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
Interface for TAP NIOs (UNIX based OSes only).
"""

import asyncio
import uuid
from .nio import NIO

import logging
log = logging.getLogger(__name__)


class NIOTAP(NIO):

    """
    Dynamips TAP NIO.

    :param hypervisor: Dynamips hypervisor instance
    :param tap_device: TAP device name (e.g. tap0)
    """

    def __init__(self, hypervisor, tap_device):

        # create an unique name
        name = 'tap-{}'.format(uuid.uuid4())
        self._tap_device = tap_device
        super().__init__(name, hypervisor)

    @asyncio.coroutine
    def create(self):

        yield from self._hypervisor.send("nio create_tap {name} {tap}".format(name=self._name, tap=self._tap_device))
        log.info("NIO TAP {name} created with device {device}".format(name=self._name, device=self._tap_device))

    @property
    def tap_device(self):
        """
        Returns the TAP device used by this NIO.

        :returns: the TAP device name
        """

        return self._tap_device

    def __json__(self):

        return {"type": "nio_tap",
                "tap_device": self._tap_device}
