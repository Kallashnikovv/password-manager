import sys
from PyQt6.QtWidgets import QApplication

from src.gui.initial_setup import initial_setup_gui
from src.gui.login_dialog import LoginDialog
from src.gui.main_window import MainWindow

from src.password_manager.cli import run_cli

def run_gui():
    app = QApplication(sys.argv)

    initial_setup_gui()

    # login dialog
    login_dialog = LoginDialog()
    login_dialog.raise_()
    login_dialog.activateWindow()
    result = login_dialog.exec()
    
    from PyQt6.QtWidgets import QDialog
    if result == QDialog.DialogCode.Accepted.value and login_dialog.ephemeral_key:
        main_window = MainWindow(login_dialog.ephemeral_key)
        main_window.show()
        main_window.raise_()
        main_window.activateWindow()
        sys.exit(app.exec())
    else:
        sys.exit(0)

def main():
    for arg in sys.argv:
        if arg == "--cli":
            run_cli()
            return
        
    run_gui()

if __name__ == "__main__":
    main()
