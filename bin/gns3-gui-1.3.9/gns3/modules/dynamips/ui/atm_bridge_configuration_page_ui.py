# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/grossmj/workspace/git/gns3-gui/gns3/modules/dynamips/ui/atm_bridge_configuration_page.ui'
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


class Ui_atmBridgeConfigPageWidget(object):

    def setupUi(self, atmBridgeConfigPageWidget):
        atmBridgeConfigPageWidget.setObjectName(_fromUtf8("atmBridgeConfigPageWidget"))
        atmBridgeConfigPageWidget.resize(432, 358)
        self.gridLayout_2 = QtGui.QGridLayout(atmBridgeConfigPageWidget)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.uiMappingGroupBox = QtGui.QGroupBox(atmBridgeConfigPageWidget)
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
        self.gridLayout_2.addWidget(self.uiMappingGroupBox, 0, 2, 3, 1)
        self.uiEthernetGroupBox = QtGui.QGroupBox(atmBridgeConfigPageWidget)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiEthernetGroupBox.sizePolicy().hasHeightForWidth())
        self.uiEthernetGroupBox.setSizePolicy(sizePolicy)
        self.uiEthernetGroupBox.setObjectName(_fromUtf8("uiEthernetGroupBox"))
        self.gridlayout = QtGui.QGridLayout(self.uiEthernetGroupBox)
        self.gridlayout.setObjectName(_fromUtf8("gridlayout"))
        self.uiEthernetPortLabel = QtGui.QLabel(self.uiEthernetGroupBox)
        self.uiEthernetPortLabel.setObjectName(_fromUtf8("uiEthernetPortLabel"))
        self.gridlayout.addWidget(self.uiEthernetPortLabel, 0, 0, 1, 1)
        self.uiEthernetPortSpinBox = QtGui.QSpinBox(self.uiEthernetGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiEthernetPortSpinBox.sizePolicy().hasHeightForWidth())
        self.uiEthernetPortSpinBox.setSizePolicy(sizePolicy)
        self.uiEthernetPortSpinBox.setMinimum(0)
        self.uiEthernetPortSpinBox.setMaximum(65535)
        self.uiEthernetPortSpinBox.setProperty("value", 1)
        self.uiEthernetPortSpinBox.setObjectName(_fromUtf8("uiEthernetPortSpinBox"))
        self.gridlayout.addWidget(self.uiEthernetPortSpinBox, 0, 1, 1, 1)
        self.gridLayout_2.addWidget(self.uiEthernetGroupBox, 1, 0, 1, 2)
        self.uiATMGroupBox = QtGui.QGroupBox(atmBridgeConfigPageWidget)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiATMGroupBox.sizePolicy().hasHeightForWidth())
        self.uiATMGroupBox.setSizePolicy(sizePolicy)
        self.uiATMGroupBox.setObjectName(_fromUtf8("uiATMGroupBox"))
        self.gridlayout1 = QtGui.QGridLayout(self.uiATMGroupBox)
        self.gridlayout1.setObjectName(_fromUtf8("gridlayout1"))
        self.uiATMPortLabel = QtGui.QLabel(self.uiATMGroupBox)
        self.uiATMPortLabel.setObjectName(_fromUtf8("uiATMPortLabel"))
        self.gridlayout1.addWidget(self.uiATMPortLabel, 0, 0, 1, 1)
        self.uiATMPortSpinBox = QtGui.QSpinBox(self.uiATMGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiATMPortSpinBox.sizePolicy().hasHeightForWidth())
        self.uiATMPortSpinBox.setSizePolicy(sizePolicy)
        self.uiATMPortSpinBox.setMinimum(0)
        self.uiATMPortSpinBox.setMaximum(65535)
        self.uiATMPortSpinBox.setProperty("value", 10)
        self.uiATMPortSpinBox.setObjectName(_fromUtf8("uiATMPortSpinBox"))
        self.gridlayout1.addWidget(self.uiATMPortSpinBox, 0, 1, 1, 1)
        self.uiATMVPILabel = QtGui.QLabel(self.uiATMGroupBox)
        self.uiATMVPILabel.setObjectName(_fromUtf8("uiATMVPILabel"))
        self.gridlayout1.addWidget(self.uiATMVPILabel, 1, 0, 1, 1)
        self.uiATMVPISpinBox = QtGui.QSpinBox(self.uiATMGroupBox)
        self.uiATMVPISpinBox.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiATMVPISpinBox.sizePolicy().hasHeightForWidth())
        self.uiATMVPISpinBox.setSizePolicy(sizePolicy)
        self.uiATMVPISpinBox.setMinimum(0)
        self.uiATMVPISpinBox.setMaximum(65535)
        self.uiATMVPISpinBox.setSingleStep(1)
        self.uiATMVPISpinBox.setProperty("value", 0)
        self.uiATMVPISpinBox.setObjectName(_fromUtf8("uiATMVPISpinBox"))
        self.gridlayout1.addWidget(self.uiATMVPISpinBox, 1, 1, 1, 1)
        self.uiATMVCILabel = QtGui.QLabel(self.uiATMGroupBox)
        self.uiATMVCILabel.setObjectName(_fromUtf8("uiATMVCILabel"))
        self.gridlayout1.addWidget(self.uiATMVCILabel, 2, 0, 1, 1)
        self.uiATMVCISpinBox = QtGui.QSpinBox(self.uiATMGroupBox)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.uiATMVCISpinBox.sizePolicy().hasHeightForWidth())
        self.uiATMVCISpinBox.setSizePolicy(sizePolicy)
        self.uiATMVCISpinBox.setMaximum(65535)
        self.uiATMVCISpinBox.setProperty("value", 100)
        self.uiATMVCISpinBox.setObjectName(_fromUtf8("uiATMVCISpinBox"))
        self.gridlayout1.addWidget(self.uiATMVCISpinBox, 2, 1, 1, 1)
        self.gridLayout_2.addWidget(self.uiATMGroupBox, 2, 0, 1, 2)
        self.uiAddPushButton = QtGui.QPushButton(atmBridgeConfigPageWidget)
        self.uiAddPushButton.setObjectName(_fromUtf8("uiAddPushButton"))
        self.gridLayout_2.addWidget(self.uiAddPushButton, 3, 0, 1, 1)
        self.uiDeletePushButton = QtGui.QPushButton(atmBridgeConfigPageWidget)
        self.uiDeletePushButton.setEnabled(False)
        self.uiDeletePushButton.setObjectName(_fromUtf8("uiDeletePushButton"))
        self.gridLayout_2.addWidget(self.uiDeletePushButton, 3, 1, 1, 1)
        spacerItem = QtGui.QSpacerItem(371, 121, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem, 4, 0, 1, 3)
        self.uiGeneralGroupBox = QtGui.QGroupBox(atmBridgeConfigPageWidget)
        self.uiGeneralGroupBox.setObjectName(_fromUtf8("uiGeneralGroupBox"))
        self.gridLayout = QtGui.QGridLayout(self.uiGeneralGroupBox)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.uiNameLabel = QtGui.QLabel(self.uiGeneralGroupBox)
        self.uiNameLabel.setObjectName(_fromUtf8("uiNameLabel"))
        self.gridLayout.addWidget(self.uiNameLabel, 0, 0, 1, 1)
        self.uiNameLineEdit = QtGui.QLineEdit(self.uiGeneralGroupBox)
        self.uiNameLineEdit.setObjectName(_fromUtf8("uiNameLineEdit"))
        self.gridLayout.addWidget(self.uiNameLineEdit, 0, 1, 1, 1)
        self.gridLayout_2.addWidget(self.uiGeneralGroupBox, 0, 0, 1, 2)

        self.retranslateUi(atmBridgeConfigPageWidget)
        QtCore.QMetaObject.connectSlotsByName(atmBridgeConfigPageWidget)
        atmBridgeConfigPageWidget.setTabOrder(self.uiEthernetPortSpinBox, self.uiATMPortSpinBox)
        atmBridgeConfigPageWidget.setTabOrder(self.uiATMPortSpinBox, self.uiATMVPISpinBox)
        atmBridgeConfigPageWidget.setTabOrder(self.uiATMVPISpinBox, self.uiATMVCISpinBox)
        atmBridgeConfigPageWidget.setTabOrder(self.uiATMVCISpinBox, self.uiAddPushButton)
        atmBridgeConfigPageWidget.setTabOrder(self.uiAddPushButton, self.uiDeletePushButton)

    def retranslateUi(self, atmBridgeConfigPageWidget):
        atmBridgeConfigPageWidget.setWindowTitle(_translate("atmBridgeConfigPageWidget", "ATM Bridge", None))
        self.uiMappingGroupBox.setTitle(_translate("atmBridgeConfigPageWidget", "Mapping", None))
        self.uiMappingTreeWidget.headerItem().setText(0, _translate("atmBridgeConfigPageWidget", "Ethernet Port", None))
        self.uiMappingTreeWidget.headerItem().setText(1, _translate("atmBridgeConfigPageWidget", "Port:VPI:VCI", None))
        self.uiEthernetGroupBox.setTitle(_translate("atmBridgeConfigPageWidget", "Ethernet side", None))
        self.uiEthernetPortLabel.setText(_translate("atmBridgeConfigPageWidget", "Port:", None))
        self.uiATMGroupBox.setTitle(_translate("atmBridgeConfigPageWidget", "ATM side", None))
        self.uiATMPortLabel.setText(_translate("atmBridgeConfigPageWidget", "Port:", None))
        self.uiATMVPILabel.setText(_translate("atmBridgeConfigPageWidget", "VPI:", None))
        self.uiATMVCILabel.setText(_translate("atmBridgeConfigPageWidget", "VCI:", None))
        self.uiAddPushButton.setText(_translate("atmBridgeConfigPageWidget", "&Add", None))
        self.uiDeletePushButton.setText(_translate("atmBridgeConfigPageWidget", "&Delete", None))
        self.uiGeneralGroupBox.setTitle(_translate("atmBridgeConfigPageWidget", "General", None))
        self.uiNameLabel.setText(_translate("atmBridgeConfigPageWidget", "Name:", None))