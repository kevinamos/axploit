# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/grossmj/workspace/git/gns3-gui/gns3/modules/dynamips/ui/atm_switch_configuration_page.ui'
#
# Created: Sun Mar 16 11:16:57 2014
#      by: PyQt4 UI code generator 4.10
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8

    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)


class Ui_atmSwitchConfigPageWidget(object):

    def setupUi(self, atmSwitchConfigPageWidget):
        atmSwitchConfigPageWidget.setObjectName(_fromUtf8("atmSwitchConfigPageWidget"))
        atmSwitchConfigPageWidget.resize(459, 419)
        self.gridLayout_2 = QtGui.QGridLayout(atmSwitchConfigPageWidget)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.uiGeneralGroupBox = QtGui.QGroupBox(atmSwitchConfigPageWidget)
        self.uiGeneralGroupBox.setObjectName(_fromUtf8("uiGeneralGroupBox"))
        self.gridLayout = QtGui.QGridLayout(self.uiGeneralGroupBox)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.uiNameLabel = QtGui.QLabel(self.uiGeneralGroupBox)
        self.uiNameLabel.setObjectName(_fromUtf8("uiNameLabel"))
        self.gridLayout.addWidget(self.uiNameLabel, 0, 0, 1, 1)
        self.uiNameLineEdit = QtGui.QLineEdit(self.uiGeneralGroupBox)
        self.uiNameLineEdit.setObjectName(_fromUtf8("uiNameLineEdit"))
        self.gridLayout.addWidget(self.uiNameLineEdit, 0, 1, 1, 1)
        self.uiVPICheckBox = QtGui.QCheckBox(self.uiGeneralGroupBox)
        self.uiVPICheckBox.setObjectName(_fromUtf8("uiVPICheckBox"))
        self.gridLayout.addWidget(self.uiVPICheckBox, 1, 0, 1, 2)
        self.gridLayout_2.addWidget(self.uiGeneralGroupBox, 0, 0, 1, 3)
        self.uiMappingGroupBox = QtGui.QGroupBox(atmSwitchConfigPageWidget)
        self.uiMappingGroupBox.setObjectName(_fromUtf8("uiMappingGroupBox"))
        self.vboxlayout = QtGui.QVBoxLayout(self.uiMappingGroupBox)
        self.vboxlayout.setObjectName(_fromUtf8("vboxlayout"))
        self.uiMappingTreeWidget = QtGui.QTreeWidget(self.uiMappingGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiMappingTreeWidget.sizePolicy().hasHeightForWidth())
        self.uiMappingTreeWidget.setSizePolicy(sizePolicy)
        self.uiMappingTreeWidget.setRootIsDecorated(False)
        self.uiMappingTreeWidget.setObjectName(_fromUtf8("uiMappingTreeWidget"))
        self.vboxlayout.addWidget(self.uiMappingTreeWidget)
        self.gridLayout_2.addWidget(self.uiMappingGroupBox, 0, 3, 3, 1)
        self.uiAddPushButton = QtGui.QPushButton(atmSwitchConfigPageWidget)
        self.uiAddPushButton.setObjectName(_fromUtf8("uiAddPushButton"))
        self.gridLayout_2.addWidget(self.uiAddPushButton, 3, 0, 1, 1)
        self.uiDeletePushButton = QtGui.QPushButton(atmSwitchConfigPageWidget)
        self.uiDeletePushButton.setEnabled(False)
        self.uiDeletePushButton.setObjectName(_fromUtf8("uiDeletePushButton"))
        self.gridLayout_2.addWidget(self.uiDeletePushButton, 3, 1, 1, 1)
        spacerItem = QtGui.QSpacerItem(213, 31, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem, 4, 2, 1, 2)
        self.uiSourceGroupBox = QtGui.QGroupBox(atmSwitchConfigPageWidget)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiSourceGroupBox.sizePolicy().hasHeightForWidth())
        self.uiSourceGroupBox.setSizePolicy(sizePolicy)
        self.uiSourceGroupBox.setObjectName(_fromUtf8("uiSourceGroupBox"))
        self.gridlayout = QtGui.QGridLayout(self.uiSourceGroupBox)
        self.gridlayout.setObjectName(_fromUtf8("gridlayout"))
        self.uiSourcePortLabel = QtGui.QLabel(self.uiSourceGroupBox)
        self.uiSourcePortLabel.setObjectName(_fromUtf8("uiSourcePortLabel"))
        self.gridlayout.addWidget(self.uiSourcePortLabel, 0, 0, 1, 1)
        self.uiSourcePortSpinBox = QtGui.QSpinBox(self.uiSourceGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiSourcePortSpinBox.sizePolicy().hasHeightForWidth())
        self.uiSourcePortSpinBox.setSizePolicy(sizePolicy)
        self.uiSourcePortSpinBox.setMinimum(0)
        self.uiSourcePortSpinBox.setMaximum(65535)
        self.uiSourcePortSpinBox.setProperty("value", 1)
        self.uiSourcePortSpinBox.setObjectName(_fromUtf8("uiSourcePortSpinBox"))
        self.gridlayout.addWidget(self.uiSourcePortSpinBox, 0, 1, 1, 1)
        self.uiSourceVPILabel = QtGui.QLabel(self.uiSourceGroupBox)
        self.uiSourceVPILabel.setObjectName(_fromUtf8("uiSourceVPILabel"))
        self.gridlayout.addWidget(self.uiSourceVPILabel, 1, 0, 1, 1)
        self.uiSourceVPISpinBox = QtGui.QSpinBox(self.uiSourceGroupBox)
        self.uiSourceVPISpinBox.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiSourceVPISpinBox.sizePolicy().hasHeightForWidth())
        self.uiSourceVPISpinBox.setSizePolicy(sizePolicy)
        self.uiSourceVPISpinBox.setMaximum(65535)
        self.uiSourceVPISpinBox.setProperty("value", 0)
        self.uiSourceVPISpinBox.setObjectName(_fromUtf8("uiSourceVPISpinBox"))
        self.gridlayout.addWidget(self.uiSourceVPISpinBox, 1, 1, 1, 1)
        self.uiSourceVCILabel = QtGui.QLabel(self.uiSourceGroupBox)
        self.uiSourceVCILabel.setObjectName(_fromUtf8("uiSourceVCILabel"))
        self.gridlayout.addWidget(self.uiSourceVCILabel, 2, 0, 1, 1)
        self.uiSourceVCISpinBox = QtGui.QSpinBox(self.uiSourceGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiSourceVCISpinBox.sizePolicy().hasHeightForWidth())
        self.uiSourceVCISpinBox.setSizePolicy(sizePolicy)
        self.uiSourceVCISpinBox.setMaximum(65535)
        self.uiSourceVCISpinBox.setProperty("value", 100)
        self.uiSourceVCISpinBox.setObjectName(_fromUtf8("uiSourceVCISpinBox"))
        self.gridlayout.addWidget(self.uiSourceVCISpinBox, 2, 1, 1, 1)
        self.gridLayout_2.addWidget(self.uiSourceGroupBox, 1, 0, 1, 3)
        self.uiDestinationGroupBox = QtGui.QGroupBox(atmSwitchConfigPageWidget)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiDestinationGroupBox.sizePolicy().hasHeightForWidth())
        self.uiDestinationGroupBox.setSizePolicy(sizePolicy)
        self.uiDestinationGroupBox.setObjectName(_fromUtf8("uiDestinationGroupBox"))
        self.gridlayout1 = QtGui.QGridLayout(self.uiDestinationGroupBox)
        self.gridlayout1.setObjectName(_fromUtf8("gridlayout1"))
        self.uiDestinationPortLabel = QtGui.QLabel(self.uiDestinationGroupBox)
        self.uiDestinationPortLabel.setObjectName(_fromUtf8("uiDestinationPortLabel"))
        self.gridlayout1.addWidget(self.uiDestinationPortLabel, 0, 0, 1, 1)
        self.uiDestinationPortSpinBox = QtGui.QSpinBox(self.uiDestinationGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiDestinationPortSpinBox.sizePolicy().hasHeightForWidth())
        self.uiDestinationPortSpinBox.setSizePolicy(sizePolicy)
        self.uiDestinationPortSpinBox.setMinimum(0)
        self.uiDestinationPortSpinBox.setMaximum(65535)
        self.uiDestinationPortSpinBox.setProperty("value", 10)
        self.uiDestinationPortSpinBox.setObjectName(_fromUtf8("uiDestinationPortSpinBox"))
        self.gridlayout1.addWidget(self.uiDestinationPortSpinBox, 0, 1, 1, 1)
        self.uiDestinationVPILabel = QtGui.QLabel(self.uiDestinationGroupBox)
        self.uiDestinationVPILabel.setObjectName(_fromUtf8("uiDestinationVPILabel"))
        self.gridlayout1.addWidget(self.uiDestinationVPILabel, 1, 0, 1, 1)
        self.uiDestinationVPISpinBox = QtGui.QSpinBox(self.uiDestinationGroupBox)
        self.uiDestinationVPISpinBox.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiDestinationVPISpinBox.sizePolicy().hasHeightForWidth())
        self.uiDestinationVPISpinBox.setSizePolicy(sizePolicy)
        self.uiDestinationVPISpinBox.setMaximum(65535)
        self.uiDestinationVPISpinBox.setProperty("value", 0)
        self.uiDestinationVPISpinBox.setObjectName(_fromUtf8("uiDestinationVPISpinBox"))
        self.gridlayout1.addWidget(self.uiDestinationVPISpinBox, 1, 1, 1, 1)
        self.uiDestinationVCILabel = QtGui.QLabel(self.uiDestinationGroupBox)
        self.uiDestinationVCILabel.setObjectName(_fromUtf8("uiDestinationVCILabel"))
        self.gridlayout1.addWidget(self.uiDestinationVCILabel, 2, 0, 1, 1)
        self.uiDestinationVCISpinBox = QtGui.QSpinBox(self.uiDestinationGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiDestinationVCISpinBox.sizePolicy().hasHeightForWidth())
        self.uiDestinationVCISpinBox.setSizePolicy(sizePolicy)
        self.uiDestinationVCISpinBox.setMaximum(65535)
        self.uiDestinationVCISpinBox.setProperty("value", 200)
        self.uiDestinationVCISpinBox.setObjectName(_fromUtf8("uiDestinationVCISpinBox"))
        self.gridlayout1.addWidget(self.uiDestinationVCISpinBox, 2, 1, 1, 1)
        self.gridLayout_2.addWidget(self.uiDestinationGroupBox, 2, 0, 1, 3)

        self.retranslateUi(atmSwitchConfigPageWidget)
        QtCore.QMetaObject.connectSlotsByName(atmSwitchConfigPageWidget)
        atmSwitchConfigPageWidget.setTabOrder(self.uiVPICheckBox, self.uiSourcePortSpinBox)
        atmSwitchConfigPageWidget.setTabOrder(self.uiSourcePortSpinBox, self.uiSourceVPISpinBox)
        atmSwitchConfigPageWidget.setTabOrder(self.uiSourceVPISpinBox, self.uiSourceVCISpinBox)
        atmSwitchConfigPageWidget.setTabOrder(self.uiSourceVCISpinBox, self.uiDestinationPortSpinBox)
        atmSwitchConfigPageWidget.setTabOrder(self.uiDestinationPortSpinBox, self.uiDestinationVPISpinBox)
        atmSwitchConfigPageWidget.setTabOrder(self.uiDestinationVPISpinBox, self.uiDestinationVCISpinBox)
        atmSwitchConfigPageWidget.setTabOrder(self.uiDestinationVCISpinBox, self.uiAddPushButton)
        atmSwitchConfigPageWidget.setTabOrder(self.uiAddPushButton, self.uiDeletePushButton)

    def retranslateUi(self, atmSwitchConfigPageWidget):
        atmSwitchConfigPageWidget.setWindowTitle(_translate("atmSwitchConfigPageWidget", "ATM Switch", None))
        self.uiGeneralGroupBox.setTitle(_translate("atmSwitchConfigPageWidget", "General", None))
        self.uiNameLabel.setText(_translate("atmSwitchConfigPageWidget", "Name:", None))
        self.uiVPICheckBox.setText(_translate("atmSwitchConfigPageWidget", "Use VPI only (VP tunnel)", None))
        self.uiMappingGroupBox.setTitle(_translate("atmSwitchConfigPageWidget", "Mapping", None))
        self.uiMappingTreeWidget.headerItem().setText(0, _translate("atmSwitchConfigPageWidget", "Port:VPI:VCI", None))
        self.uiMappingTreeWidget.headerItem().setText(1, _translate("atmSwitchConfigPageWidget", "Port:VPI:VCI", None))
        self.uiAddPushButton.setText(_translate("atmSwitchConfigPageWidget", "&Add", None))
        self.uiDeletePushButton.setText(_translate("atmSwitchConfigPageWidget", "&Delete", None))
        self.uiSourceGroupBox.setTitle(_translate("atmSwitchConfigPageWidget", "Source", None))
        self.uiSourcePortLabel.setText(_translate("atmSwitchConfigPageWidget", "Port:", None))
        self.uiSourceVPILabel.setText(_translate("atmSwitchConfigPageWidget", "VPI:", None))
        self.uiSourceVCILabel.setText(_translate("atmSwitchConfigPageWidget", "VCI:", None))
        self.uiDestinationGroupBox.setTitle(_translate("atmSwitchConfigPageWidget", "Destination", None))
        self.uiDestinationPortLabel.setText(_translate("atmSwitchConfigPageWidget", "Port:", None))
        self.uiDestinationVPILabel.setText(_translate("atmSwitchConfigPageWidget", "VPI:", None))
        self.uiDestinationVCILabel.setText(_translate("atmSwitchConfigPageWidget", "VCI:", None))