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

import pytest
import aiohttp
import asyncio
import os
import stat
import socket
import sys
from tests.utils import asyncio_patch


from unittest.mock import patch, MagicMock, PropertyMock

pytestmark = pytest.mark.skipif(sys.platform.startswith("win"), reason="Not supported on Windows")

if not sys.platform.startswith("win"):
    from gns3server.modules.iou.iou_vm import IOUVM
    from gns3server.modules.iou.iou_error import IOUError
    from gns3server.modules.iou import IOU

from gns3server.config import Config


@pytest.fixture(scope="module")
def manager(port_manager):
    m = IOU.instance()
    m.port_manager = port_manager
    return m


@pytest.fixture(scope="function")
def vm(project, manager, tmpdir, fake_iou_bin, iourc_file):
    fake_file = str(tmpdir / "iouyap")
    with open(fake_file, "w+") as f:
        f.write("1")

    vm = IOUVM("test", "00010203-0405-0607-0809-0a0b0c0d0e0f", project, manager)
    config = manager.config.get_section_config("IOU")
    config["iouyap_path"] = fake_file
    config["iourc_path"] = iourc_file
    manager.config.set_section_config("IOU", config)

    vm.path = fake_iou_bin
    return vm


@pytest.fixture
def iourc_file(tmpdir):
    path = str(tmpdir / "iourc")
    with open(path, "w+") as f:
        hostname = socket.gethostname()
        f.write("[license]\n{} = aaaaaaaaaaaaaaaa;".format(hostname))
    return path


@pytest.fixture
def fake_iou_bin(tmpdir):
    """Create a fake IOU image on disk"""

    os.makedirs(str(tmpdir / "IOU"), exist_ok=True)
    path = str(tmpdir / "IOU" / "iou.bin")
    with open(path, "w+") as f:
        f.write('\x7fELF\x01\x01\x01')
    os.chmod(path, stat.S_IREAD | stat.S_IEXEC)
    return path


def test_vm(project, manager):
    vm = IOUVM("test", "00010203-0405-0607-0809-0a0b0c0d0e0f", project, manager)
    assert vm.name == "test"
    assert vm.id == "00010203-0405-0607-0809-0a0b0c0d0e0f"


def test_vm_initial_config_content(project, manager):
    vm = IOUVM("test", "00010203-0405-0607-0808-0a0b0c0d0e0f", project, manager)
    vm.initial_config_content = "hostname %h"
    assert vm.name == "test"
    assert vm.initial_config_content == "hostname test"
    assert vm.id == "00010203-0405-0607-0808-0a0b0c0d0e0f"


@patch("gns3server.config.Config.get_section_config", return_value={"iouyap_path": "/bin/test_fake"})
def test_vm_invalid_iouyap_path(project, manager, loop):
    with pytest.raises(IOUError):
        vm = IOUVM("test", "00010203-0405-0607-0809-0a0b0c0d0e0e", project, manager)
        loop.run_until_complete(asyncio.async(vm.start()))


def test_start(loop, vm, monkeypatch):

    mock_process = MagicMock()
    with patch("gns3server.modules.iou.iou_vm.IOUVM._check_requirements", return_value=True):
        with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._check_iou_licence", return_value=True):
            with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_ioucon", return_value=True):
                with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_iouyap", return_value=True):
                    with asyncio_patch("asyncio.create_subprocess_exec", return_value=mock_process):
                        mock_process.returncode = None
                        loop.run_until_complete(asyncio.async(vm.start()))
                        assert vm.is_running()


def test_start_with_iourc(loop, vm, monkeypatch, tmpdir):

    fake_file = str(tmpdir / "iourc")
    with open(fake_file, "w+") as f:
        f.write("1")
    mock_process = MagicMock()
    with patch("gns3server.config.Config.get_section_config", return_value={"iourc_path": fake_file, "iouyap_path": vm.iouyap_path}):
        with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._check_requirements", return_value=True):
            with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._check_iou_licence", return_value=True):
                with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_ioucon", return_value=True):
                    with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_iouyap", return_value=True):
                        with asyncio_patch("asyncio.create_subprocess_exec", return_value=mock_process) as exec_mock:
                            mock_process.returncode = None
                            loop.run_until_complete(asyncio.async(vm.start()))
                            assert vm.is_running()
                            arsgs, kwargs = exec_mock.call_args
                            assert kwargs["env"]["IOURC"] == fake_file


def test_rename_nvram_file(loop, vm, monkeypatch):
    """
    It should rename the nvram file to the correct name before launching the VM
    """

    with open(os.path.join(vm.working_dir, "nvram_0000{}".format(vm.application_id + 1)), 'w+') as f:
        f.write("1")

    with open(os.path.join(vm.working_dir, "vlan.dat-0000{}".format(vm.application_id + 1)), 'w+') as f:
        f.write("1")

    vm._rename_nvram_file()
    assert os.path.exists(os.path.join(vm.working_dir, "nvram_0000{}".format(vm.application_id)))
    assert os.path.exists(os.path.join(vm.working_dir, "vlan.dat-0000{}".format(vm.application_id)))


def test_stop(loop, vm):
    process = MagicMock()

    # Wait process kill success
    future = asyncio.Future()
    future.set_result(True)
    process.wait.return_value = future

    with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._check_requirements", return_value=True):
        with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_ioucon", return_value=True):
            with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_iouyap", return_value=True):
                with asyncio_patch("asyncio.create_subprocess_exec", return_value=process):
                    with asyncio_patch("gns3server.utils.asyncio.wait_for_process_termination"):
                        loop.run_until_complete(asyncio.async(vm.start()))
                        process.returncode = None
                        assert vm.is_running()
                        loop.run_until_complete(asyncio.async(vm.stop()))
                        assert vm.is_running() is False
                        process.terminate.assert_called_with()


def test_reload(loop, vm, fake_iou_bin):
    process = MagicMock()

    # Wait process kill success
    future = asyncio.Future()
    future.set_result(True)
    process.wait.return_value = future
    process.returncode = None

    with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._check_requirements", return_value=True):
        with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_ioucon", return_value=True):
            with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._start_iouyap", return_value=True):
                with asyncio_patch("asyncio.create_subprocess_exec", return_value=process):
                    with asyncio_patch("gns3server.utils.asyncio.wait_for_process_termination"):
                        loop.run_until_complete(asyncio.async(vm.start()))
                        assert vm.is_running()
                        loop.run_until_complete(asyncio.async(vm.reload()))
                        assert vm.is_running() is True
                        process.terminate.assert_called_with()


def test_close(vm, port_manager, loop):
    with asyncio_patch("gns3server.modules.iou.iou_vm.IOUVM._check_requirements", return_value=True):
        with asyncio_patch("asyncio.create_subprocess_exec", return_value=MagicMock()):
            vm.start()
            port = vm.console
            loop.run_until_complete(asyncio.async(vm.close()))
            # Raise an exception if the port is not free
            port_manager.reserve_tcp_port(port, vm.project)
            assert vm.is_running() is False


def test_path(vm, fake_iou_bin):

    vm.path = fake_iou_bin
    assert vm.path == fake_iou_bin


def test_path_12_location(vm, fake_iou_bin):

    # In 1.2 users uploaded images to the images roots
    # after the migration their images are inside images/IOU
    # but old topologies use old path
    vm.path = fake_iou_bin.replace("/IOU", "")
    assert vm.path == fake_iou_bin


def test_path_relative(vm, fake_iou_bin, tmpdir):

    config = Config.instance()
    config.set("Server", "images_path", str(tmpdir))
    vm.path = "iou.bin"
    assert vm.path == fake_iou_bin


def test_path_invalid_bin(vm, tmpdir):

    path = str(tmpdir / "test.bin")
    with pytest.raises(IOUError):
        vm.path = path

    with open(path, "w+") as f:
        f.write("BUG")

    with pytest.raises(IOUError):
        vm.path = path


def test_create_netmap_config(vm):

    vm._create_netmap_config()
    netmap_path = os.path.join(vm.working_dir, "NETMAP")

    with open(netmap_path) as f:
        content = f.read()

    assert "513:0/0    1:0/0" in content
    assert "513:15/3    1:15/3" in content


def test_build_command(vm, loop):

    assert loop.run_until_complete(asyncio.async(vm._build_command())) == [vm.path, "-L", str(vm.application_id)]


def test_build_command_initial_config(vm, loop):

    filepath = os.path.join(vm.working_dir, "initial-config.cfg")
    with open(filepath, "w+") as f:
        f.write("service timestamps debug datetime msec\nservice timestamps log datetime msec\nno service password-encryption")

    assert loop.run_until_complete(asyncio.async(vm._build_command())) == [vm.path, "-L", "-c", os.path.basename(vm.initial_config_file), str(vm.application_id)]


def test_get_initial_config(vm):

    content = "service timestamps debug datetime msec\nservice timestamps log datetime msec\nno service password-encryption"
    vm.initial_config = content
    assert vm.initial_config == content


def test_update_initial_config(vm):
    content = "service timestamps debug datetime msec\nservice timestamps log datetime msec\nno service password-encryption"
    vm.initial_config = content
    filepath = os.path.join(vm.working_dir, "initial-config.cfg")
    assert os.path.exists(filepath)
    with open(filepath) as f:
        assert f.read() == content


def test_update_initial_config_empty(vm):
    content = "service timestamps debug datetime msec\nservice timestamps log datetime msec\nno service password-encryption"
    vm.initial_config = content
    filepath = os.path.join(vm.working_dir, "initial-config.cfg")
    assert os.path.exists(filepath)
    with open(filepath) as f:
        assert f.read() == content
    vm.initial_config = ""
    with open(filepath) as f:
        assert f.read() == content


def test_update_initial_config_content_hostname(vm):
    content = "hostname %h\n"
    vm.name = "pc1"
    vm.initial_config_content = content
    with open(vm.initial_config_file) as f:
        assert f.read() == "hostname pc1\n"


def test_change_name(vm, tmpdir):
    path = os.path.join(vm.working_dir, "initial-config.cfg")
    vm.name = "world"
    with open(path, 'w+') as f:
        f.write("hostname world")
    vm.name = "hello"
    assert vm.name == "hello"
    with open(path) as f:
        assert f.read() == "hostname hello"


def test_library_check(loop, vm):

    with asyncio_patch("gns3server.utils.asyncio.subprocess_check_output", return_value="") as mock:

        loop.run_until_complete(asyncio.async(vm._library_check()))

    with asyncio_patch("gns3server.utils.asyncio.subprocess_check_output", return_value="libssl => not found") as mock:
        with pytest.raises(IOUError):
            loop.run_until_complete(asyncio.async(vm._library_check()))


def test_enable_l1_keepalives(loop, vm):

    with asyncio_patch("gns3server.utils.asyncio.subprocess_check_output", return_value="***************************************************************\n\n-l		Enable Layer 1 keepalive messages\n-u <n>		UDP port base for distributed networks\n") as mock:

        command = ["test"]
        loop.run_until_complete(asyncio.async(vm._enable_l1_keepalives(command)))
        assert command == ["test", "-l"]

    with asyncio_patch("gns3server.utils.asyncio.subprocess_check_output", return_value="***************************************************************\n\n-u <n>		UDP port base for distributed networks\n") as mock:

        command = ["test"]
        with pytest.raises(IOUError):
            loop.run_until_complete(asyncio.async(vm._enable_l1_keepalives(command)))
            assert command == ["test"]


def test_start_capture(vm, tmpdir, manager, free_console_port, loop):

    output_file = str(tmpdir / "test.pcap")
    nio = manager.create_nio(vm.iouyap_path, {"type": "nio_udp", "lport": free_console_port, "rport": free_console_port, "rhost": "192.168.1.2"})
    vm.adapter_add_nio_binding(0, 0, nio)
    loop.run_until_complete(asyncio.async(vm.start_capture(0, 0, output_file)))
    assert vm._adapters[0].get_nio(0).capturing


def test_stop_capture(vm, tmpdir, manager, free_console_port, loop):

    output_file = str(tmpdir / "test.pcap")
    nio = manager.create_nio(vm.iouyap_path, {"type": "nio_udp", "lport": free_console_port, "rport": free_console_port, "rhost": "192.168.1.2"})
    vm.adapter_add_nio_binding(0, 0, nio)
    loop.run_until_complete(vm.start_capture(0, 0, output_file))
    assert vm._adapters[0].get_nio(0).capturing
    loop.run_until_complete(asyncio.async(vm.stop_capture(0, 0)))
    assert vm._adapters[0].get_nio(0).capturing is False


def test_get_legacy_vm_workdir():

    assert IOU.get_legacy_vm_workdir(42, "bla") == "iou/device-42"


def test_invalid_iou_file(loop, vm, iourc_file):

    hostname = socket.gethostname()

    loop.run_until_complete(asyncio.async(vm._check_iou_licence()))

    # Missing ;
    with pytest.raises(IOUError):
        with open(iourc_file, "w+") as f:
            f.write("[license]\n{} = aaaaaaaaaaaaaaaa".format(hostname))
        loop.run_until_complete(asyncio.async(vm._check_iou_licence()))

    # Key too short
    with pytest.raises(IOUError):
        with open(iourc_file, "w+") as f:
            f.write("[license]\n{} = aaaaaaaaaaaaaa;".format(hostname))
        loop.run_until_complete(asyncio.async(vm._check_iou_licence()))

    # Invalid hostname
    with pytest.raises(IOUError):
        with open(iourc_file, "w+") as f:
            f.write("[license]\nbla = aaaaaaaaaaaaaa;")
        loop.run_until_complete(asyncio.async(vm._check_iou_licence()))

    # Missing licence section
    with pytest.raises(IOUError):
        with open(iourc_file, "w+") as f:
            f.write("[licensetest]\n{} = aaaaaaaaaaaaaaaa;")
        loop.run_until_complete(asyncio.async(vm._check_iou_licence()))

    # Broken config file
    with pytest.raises(IOUError):
        with open(iourc_file, "w+") as f:
            f.write("[")
        loop.run_until_complete(asyncio.async(vm._check_iou_licence()))

    # Missing file
    with pytest.raises(IOUError):
        os.remove(iourc_file)
        loop.run_until_complete(asyncio.async(vm._check_iou_licence()))


def test_iourc_content(vm):

    vm.iourc_content = "test"

    with open(os.path.join(vm.temporary_directory, "iourc")) as f:
        assert f.read() == "test"
