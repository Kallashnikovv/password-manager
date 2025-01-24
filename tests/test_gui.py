import pytest
import os
from PyQt6.QtWidgets import QApplication, QDialog
from PyQt6.QtCore import Qt
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow

@pytest.fixture
def app(qtbot):
    return QApplication([])

def test_login_dialog(qtbot):
    dialog = LoginDialog()
    qtbot.addWidget(dialog)
    qtbot.waitExposed(dialog)
    
    # Simulate user interaction
    qtbot.mouseClick(dialog.cancel_btn, Qt.MouseButton.LeftButton)
    
    # Check if the dialog was rejected
    assert dialog.result() == QDialog.DialogCode.Rejected.value

def test_main_window(qtbot):
    ephemeral_key = os.urandom(32)
    window = MainWindow(ephemeral_key)
    qtbot.addWidget(window)
    qtbot.waitExposed(window)
    
    # Simulate user interaction
    qtbot.mouseClick(window.quit_button, Qt.MouseButton.LeftButton)
    
    # Check if the window is still visible
    assert window.isVisible() == False