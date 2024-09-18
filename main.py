import winreg
import os
import sys
import subprocess

# Ścieżka do skryptu Python, który chcesz uruchomić
this_catalog = os.getcwd()
script_path = f"{this_catalog}\\passwordmanager.py"

# Nazwa wpisu w menu kontekstowym
menu_name = "Open Password Manager"

def install_requirements():
    """Installs packages from requirements.txt."""
    requirements_path = os.path.join(this_catalog, 'requirements.txt')
    
    if os.path.exists(requirements_path):
        print("Installing packages from requirements.txt...")
        # Komenda do instalacji paczek
        command = [sys.executable, '-m', 'pip', 'install', '-r', requirements_path]
        
        try:
            subprocess.check_call(command)
            print("Packages installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install packages: {e}")
    else:
        print("requirements.txt not found. Skipping package installation.")

def add_context_menu_entry():
    try:
        # Instalacja paczek przed dodaniem wpisu do rejestru
        install_requirements()
        
        # Dodaj wpis do rejestru
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"Directory\\Background\\shell\\{menu_name}") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, menu_name)
        
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"Directory\\Background\\shell\\{menu_name}\\command") as key:
            # PowerShell uruchamia skrypt Python jako administrator
            command = f"powershell.exe -Command \"Start-Process python -ArgumentList '{script_path}' -Verb RunAs\""
            winreg.SetValue(key, "", winreg.REG_SZ, command)
        
        print(f"Context menu entry '{menu_name}' added successfully.")
    except Exception as e:
        print(f"Failed to add context menu entry: {e}")

if __name__ == "__main__":
    add_context_menu_entry()