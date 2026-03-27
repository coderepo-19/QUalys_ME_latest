import os
import subprocess
import sys
import shutil

# Dynamic path detection
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../"))

def run_command(command, cwd=None):
    print(f"Running: {' '.join(command)}")
    try:
        subprocess.check_call(command, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return False
    return True

def setup():
    print("=================================================")
    print("      Qualys-ME Environment Setup (Python)       ")
    print("=================================================")
    
    os.chdir(PROJECT_ROOT)

    # 1. Create Virtual Environment
    if not os.path.exists(".venv"):
        print("[1/4] Creating virtual environment (.venv) at project root...")
        if not run_command([sys.executable, "-m", "venv", ".venv"]):
            return
    else:
        print("[1/4] Virtual environment (.venv) already exists.")

    # 2. Determine Paths
    if sys.platform == "win32":
        pip_path = os.path.join(".venv", "Scripts", "pip.exe")
        python_path = os.path.join(".venv", "Scripts", "python.exe")
    else:
        pip_path = os.path.join(".venv", "bin", "pip")
        python_path = os.path.join(".venv", "bin", "python")

    # 3. Install Requirements
    print("[2/4] Upgrading pip and installing requirements...")
    if not run_command([python_path, "-m", "pip", "install", "--upgrade", "pip"]):
        return
    if not run_command([python_path, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"]):
        return

    # 4. Setup .env file
    print("[3/4] Initializing environment variables...")
    template = os.path.join("Config", ".env_template")
    env_file = os.path.join("Config", ".env")

    if os.path.exists(template):
        if not os.path.exists(env_file):
            shutil.copy(template, env_file)
            print("[SUCCESS] Created Config/.env from template.")
        else:
            print("[INFO] Config/.env already exists. Skipping copy.")
    else:
        print(f"[WARN] Template not found: {template}")

    # 5. Verify
    print("[4/4] Verifying installation...")
    run_command([pip_path, "list"])

    print("=================================================")
    print("           Setup Completed Successfully!         ")
    print("=================================================")
    if sys.platform == "win32":
        print("To activate on Windows (PowerShell): .venv\\Scripts\\Activate.ps1")
    else:
        print("To activate on Linux/macOS: source .venv/bin/activate")
    print("=================================================")

if __name__ == "__main__":
    setup()
