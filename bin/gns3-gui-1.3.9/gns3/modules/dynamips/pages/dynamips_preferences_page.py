# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 GNS3 Technologies Inc.
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
Configuration page for Dynamips preferences.
"""

import os
import sys
from gns3.qt import QtGui
from gns3.servers import Servers
from .. import Dynamips
from ..ui.dynamips_preferences_page_ui import Ui_DynamipsPreferencesPageWidget
from ..settings import DYNAMIPS_SETTINGS


class DynamipsPreferencesPage(QtGui.QWidget, Ui_DynamipsPreferencesPageWidget):

    """
    QWidget preference page for Dynamips.
    """

    def __init__(self):

        QtGui.QWidget.__init__(self)
        self.setupUi(self)

        # connect signals
        self.uiDynamipsPathToolButton.clicked.connect(self._dynamipsPathBrowserSlot)
        self.uiGhostIOSSupportCheckBox.stateChanged.connect(self._ghostIOSSupportSlot)
        self.uiRestoreDefaultsPushButton.clicked.connect(self._restoreDefaultsSlot)
        self.uiUseLocalServercheckBox.stateChanged.connect(self._useLocalServerSlot)

    def _dynamipsPathBrowserSlot(self):
        """
        Slot to open a file browser and select Dynamips executable.
        """

        file_filter = ""
        if sys.platform.startswith("win"):
            file_filter = "Executable (*.exe);;All files (*.*)"
        path = QtGui.QFileDialog.getOpenFileName(self, "Select Dynamips", ".", file_filter)
        if not path:
            return

        if not os.access(path, os.X_OK):
            QtGui.QMessageBox.critical(self, "Dynamips", "{} is not an executable".format(os.path.basename(path)))
            return

        self.uiDynamipsPathLineEdit.setText(path)

    def _ghostIOSSupportSlot(self, state):
        """
        Slot to have the mmap checkBox checked if ghost IOS is checked.
        Ghost IOS is dependent on the mmap feature.

        :param state: state of the ghost IOS checkBox
        """

        if state:
            self.uiMmapSupportCheckBox.setChecked(True)

    def _restoreDefaultsSlot(self):
        """
        Slot to populate the page widgets with the default settings.
        """

        self._populateWidgets(DYNAMIPS_SETTINGS)

    def _useLocalServerSlot(self, state):
        """
        Slot to enable or not local server settings.
        """

        if state:
            self.uiDynamipsPathLineEdit.setEnabled(True)
            self.uiDynamipsPathToolButton.setEnabled(True)
            self.uiAllocateAuxConsolePortsCheckBox.setEnabled(True)
            self.uiGhostIOSSupportCheckBox.setEnabled(True)
            self.uiMmapSupportCheckBox.setEnabled(True)
            self.uiSparseMemorySupportCheckBox.setEnabled(True)
        else:
            self.uiDynamipsPathLineEdit.setEnabled(False)
            self.uiDynamipsPathToolButton.setEnabled(False)
            self.uiAllocateAuxConsolePortsCheckBox.setEnabled(False)
            self.uiGhostIOSSupportCheckBox.setEnabled(False)
            self.uiMmapSupportCheckBox.setEnabled(False)
            self.uiSparseMemorySupportCheckBox.setEnabled(False)

    def _populateWidgets(self, settings):
        """
        Populates the widgets with the settings.

        :param settings: Dynamips settings
        """

        self.uiDynamipsPathLineEdit.setText(settings["dynamips_path"])
        self.uiAllocateAuxConsolePortsCheckBox.setChecked(settings["allocate_aux_console_ports"])
        self.uiUseLocalServercheckBox.setChecked(settings["use_local_server"])
        self.uiGhostIOSSupportCheckBox.setChecked(settings["ghost_ios_support"])
        self.uiMmapSupportCheckBox.setChecked(settings["mmap_support"])
        self.uiSparseMemorySupportCheckBox.setChecked(settings["sparse_memory_support"])

    def loadPreferences(self):
        """
        Loads the Dynamips preferences.
        """

        dynamips_settings = Dynamips.instance().settings()
        self._populateWidgets(dynamips_settings)

    def savePreferences(self):
        """
        Saves the Dynamips preferences.
        """

        new_settings = {}
        new_settings["dynamips_path"] = self.uiDynamipsPathLineEdit.text()
        new_settings["allocate_aux_console_ports"] = self.uiAllocateAuxConsolePortsCheckBox.isChecked()
        new_settings["use_local_server"] = self.uiUseLocalServercheckBox.isChecked()
        new_settings["ghost_ios_support"] = self.uiGhostIOSSupportCheckBox.isChecked()
        new_settings["mmap_support"] = self.uiMmapSupportCheckBox.isChecked()
        new_settings["sparse_memory_support"] = self.uiSparseMemorySupportCheckBox.isChecked()
        Dynamips.instance().setSettings(new_settings)
