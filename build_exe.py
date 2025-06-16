import PyInstaller.__main__
import sys
import os
import subprocess
import importlib.util

def create_requirements_file():
    """Create a requirements.txt file for the project"""
    requirements_content = """# TAT License Manager Requirements
PyInstaller>=6.0.0
cryptography>=40.0.0
cffi>=1.15.0
pycparser>=2.20
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements_content)
    print("✓ Created requirements.txt file")

def check_and_install_requirements():
    """Check for required packages and install them if missing"""
    required_packages = [
        'PyInstaller',
        'cryptography', 
        'cffi',
        'pycparser'
    ]
    
    missing_packages = []
    
    print("Checking required packages...")
    
    for package in required_packages:
        try:
            # Try to import the package
            __import__(package.lower())
            print(f"✓ {package} is already installed")
        except ImportError:
            print(f"✗ {package} is missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\nInstalling missing packages: {', '.join(missing_packages)}")
        
        # Try installing from requirements.txt first if it exists
        if os.path.exists('requirements.txt'):
            try:
                print("Installing from requirements.txt...")
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
                ], capture_output=True, text=True, check=True)
                print("✓ Installed all packages from requirements.txt")
            except subprocess.CalledProcessError:
                print("! Failed to install from requirements.txt, trying individual packages...")
                install_individual_packages(missing_packages)
        else:
            install_individual_packages(missing_packages)
    else:
        print("✓ All required packages are installed")

def install_individual_packages(packages):
    """Install packages individually"""
    try:
        for package in packages:
            print(f"Installing {package}...")
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package
            ], capture_output=True, text=True, check=True)
            print(f"✓ {package} installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error installing packages: {e}")
        print("Please install the required packages manually:")
        for package in packages:
            print(f"  pip install {package}")
        sys.exit(1)

def build_executable():
    """Build the executable with PyInstaller"""
    # Build arguments for PyInstaller
    args = [
        '--clean',
        '--onefile',
        '--windowed',
        '--icon=icon.ico',
        '--name=TAT_License_Manager_v1.0',
        
        # Add the icon as a data file so it's bundled with the exe
        '--add-data=icon.ico;.',
        
        # Collect all packages that might be needed
        '--collect-all=cryptography',
        '--collect-all=cffi',
        '--collect-all=pycparser',
        
        # Include data files for cryptography if any
        '--copy-metadata=cryptography',
        '--copy-metadata=cffi',
        
        # The main script
        'license_manager.py'
    ]

    print("\nBuilding TAT License Manager with comprehensive dependencies and bundled icon...")
    PyInstaller.__main__.run(args)
    print("\n" + "="*60)
    print("Build complete! Check the dist folder for TAT_License_Manager_v1.0.exe")
    print("The icon.ico file is now bundled within the executable.")
    print("="*60)

def main():
    """Main function to check requirements and build executable"""
    print("TAT License Manager - Executable Builder")
    print("="*60)
    
    # Check if icon file exists
    if not os.path.exists('icon.ico'):
        print("Error: icon.ico file not found in current directory")
        print("Please ensure icon.ico is present before building")
        sys.exit(1)
    
    # Check if main script exists
    if not os.path.exists('license_manager.py'):
        print("Error: license_manager.py file not found in current directory")
        print("Please ensure license_manager.py is present before building")
        sys.exit(1)
    
    # Create requirements.txt if it doesn't exist
    if not os.path.exists('requirements.txt'):
        print("Creating requirements.txt file...")
        create_requirements_file()
    
    # Check and install requirements
    check_and_install_requirements()
    
    # Build the executable
    build_executable()

if __name__ == "__main__":
    main() 