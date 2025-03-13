# TAT License Keygen

## Overview

The TAT License Keygen is a Python application designed to generate, manage, and validate license keys for software applications. It supports multiple types of license keys, including those based on MAC addresses and baseboard serial numbers. The application features a user-friendly Tkinter GUI and utilizes secure encryption methods to protect license data.

## Features

- **License Key Generation**: Create secure license keys based on device identifiers.
- **Device Management**: Register multiple devices for a single license key.
- **Expiry Dates**: Set expiry dates for licenses to control access.
- **Encryption**: Uses symmetric encryption to securely store license keys.
- **Cross-Platform**: Designed to work on Windows, macOS, and Linux systems.
- **Dark Theme**: A modern dark theme for better user experience.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/tat-license-manager.git
   cd tat-license-manager
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) If you want to create an executable, install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

## Usage

1. Run the application:
   ```bash
   python license_manager.py
   ```

2. Use the GUI to generate license keys:
   - Enter the device identifier (MAC address or baseboard serial).
   - Set the device limit and expiry date if needed.
   - Click "Generate License Key" to create a new license.

3. The generated license key will be displayed in the output section and can be saved to a file.

## Creating an Executable

To create a standalone executable for your application, use PyInstaller:

```bash
pyinstaller --onefile --windowed --icon=icon.ico license_manager.py
```

This will generate an executable in the `dist` directory.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI framework.
- [Cryptography](https://cryptography.io/en/latest/) for secure encryption methods.