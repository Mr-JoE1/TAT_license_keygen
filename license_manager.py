import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import os
from datetime import datetime, timedelta
import re
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class LicenseManagerApp:
    # This is a fixed salt used for key derivation - must match the validator
    SALT = b'TAT_LICENSE_SYSTEM_SALT'
    
    # This is a fixed password used for all licenses - must match the validator
    SECRET_PASSWORD = b'eng.mohamed.maher2016@gmail.com'
    
    def __init__(self, root):
        self.root = root
        self.root.title(" TAT License Keygen v1.0")
        self.root.geometry("600x700")
        self.root.minsize(600, 700)
        self.root.iconbitmap("icon.ico")
        # Set dark theme
        self.style = ttk.Style()
        self.set_dark_theme()
        
        # Variables
        self.identifier_var = tk.StringVar()
        self.identifier_type_var = tk.StringVar(value="mac")
        self.device_limit_var = tk.StringVar(value="10")
        self.has_expiry_var = tk.BooleanVar(value=False)
        self.registered_devices = []
        self.expiry_date = None
        
        # Date variables
        self.year_var = tk.StringVar(value=str(datetime.now().year + 1))
        self.month_var = tk.StringVar(value=str(datetime.now().month))
        self.day_var = tk.StringVar(value=str(datetime.now().day))
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create UI elements
        self._create_identifier_section()
        self._create_license_options_section()
        self._create_devices_section()
        self._create_output_section()
        self._create_buttons_section()
        
    def set_dark_theme(self):
        """Set dark theme for the application"""
        # Define colors - darker theme with better contrast
        bg_color = "#1E1E1E"         # Darker background
        fg_color = "#E0E0E0"         # Slightly softer white text
        input_bg = "#2D2D2D"         # Darker input background
        input_fg = "#000000"         # Black text for input fields
        button_bg = "#2D2D2D"        # Dark button background
        button_outline = "#0D6EFD"   # Blue outline for buttons
        accent_color = "#0D6EFD"     # Matching accent color
        highlight_color = "#3C3C3C"  # Highlight color for selections
        border_color = "#555555"     # Border color for sections
        
        # Configure ttk styles
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        
        # Button styles with improved colors
        self.style.configure("TButton", 
                            background=button_bg, 
                            foreground=fg_color, 
                            focuscolor=button_outline,
                            bordercolor=button_outline,
                            lightcolor=button_outline,
                            darkcolor=button_outline,
                            borderwidth=1,
                            relief="solid",
                            padding=5)
        
        self.style.map("TButton", 
            background=[("active", "#3D3D3D"), ("pressed", "#252525")],
            foreground=[("active", "#FFFFFF")],
            bordercolor=[("active", "#1E90FF")])
        
        # Checkbutton and Radiobutton styles
        self.style.configure("TCheckbutton", 
                            background=bg_color, 
                            foreground=fg_color, 
                            indicatorcolor=input_bg)
        
        self.style.map("TCheckbutton",
                     indicatorcolor=[("selected", accent_color)])
        
        self.style.configure("TRadiobutton", 
                            background=bg_color, 
                            foreground=fg_color, 
                            indicatorcolor=input_bg)
        
        self.style.map("TRadiobutton",
                     indicatorcolor=[("selected", accent_color)])
        
        # Entry fields with darker background
        self.style.configure("TEntry", 
                           fieldbackground=input_bg, 
                           foreground=fg_color,
                           bordercolor=border_color,
                           darkcolor=input_bg,
                           lightcolor=input_bg,
                           borderwidth=1)
        
        # Combobox with darker colors
        self.style.configure("TCombobox", 
                           fieldbackground=input_bg, 
                           background=input_bg, 
                           foreground=fg_color,
                           arrowcolor=fg_color,
                           bordercolor=border_color)
        
        self.style.map("TCombobox", 
            fieldbackground=[("readonly", input_bg)],
            selectbackground=[("readonly", highlight_color)],
            selectforeground=[("readonly", fg_color)])
        
        # Spinbox styling
        self.style.configure("TSpinbox",
                           fieldbackground=input_bg,
                           foreground=fg_color,
                           buttonbackground=input_bg,
                           arrowcolor=fg_color)
        
        # Configure root and other widget colors
        self.root.configure(bg=bg_color)
        
        # Custom styles for sections
        self.style.configure("Section.TFrame", 
                           background=bg_color, 
                           relief="groove", 
                           borderwidth=1, 
                           bordercolor=border_color)
        
        self.style.configure("Section.TLabel", 
                           background=bg_color, 
                           foreground=accent_color, 
                           font=("Arial", 12, "bold"))
        
        # Special button styles
        self.style.configure("Generate.TButton", 
                           background="#252525", 
                           foreground=fg_color,
                           bordercolor="#198754",
                           lightcolor="#198754",
                           darkcolor="#198754",
                           relief="solid",
                           borderwidth=1,
                           font=("Arial", 11, "bold"),
                           padding=6)
        
        self.style.map("Generate.TButton", 
                     background=[("active", "#353535"), ("pressed", "#202020")],
                     foreground=[("active", "#FFFFFF")],
                     bordercolor=[("active", "#27AE60")])
        
        # Style for completely dark entry fields with black text
        self.style.configure("Dark.TEntry",
                            fieldbackground=input_bg,
                            foreground=input_fg,  # Black text
                            insertcolor="#000000",
                            bordercolor=border_color,
                            lightcolor=border_color,
                            darkcolor=border_color)
        
        # Style for spinbox with black text
        self.style.configure("Dark.TSpinbox",
                           fieldbackground=input_bg,
                           foreground=input_fg,  # Black text
                           buttonbackground=input_bg,
                           arrowcolor=fg_color)
        
        # Additional configuration for tk native widgets
        text_bg = "#2D2D2D"
        text_fg = "#E0E0E0"
        text_select_bg = "#0D6EFD"
        text_select_fg = "#FFFFFF"
        text_insert_bg = "#E0E0E0"
        
        self.root.option_add("*Text.background", text_bg)
        self.root.option_add("*Text.foreground", text_fg)
        self.root.option_add("*Text.selectBackground", text_select_bg)
        self.root.option_add("*Text.selectForeground", text_select_fg)
        self.root.option_add("*Text.insertBackground", text_insert_bg)
        
        # Fix for native buttons and other widgets that might not follow ttk styling
        self.root.option_add("*Button.background", button_bg)
        self.root.option_add("*Button.foreground", fg_color)
        self.root.option_add("*Button.highlightBackground", button_bg)
        self.root.option_add("*Button.highlightColor", button_outline)
        self.root.option_add("*Button.activeBackground", "#3D3D3D")
        self.root.option_add("*Button.activeForeground", "#FFFFFF")
        
        # Fix for entry widgets
        self.root.option_add("*Entry.background", input_bg)
        self.root.option_add("*Entry.foreground", fg_color)
        self.root.option_add("*Entry.selectBackground", text_select_bg)
        self.root.option_add("*Entry.selectForeground", text_select_fg)
        self.root.option_add("*Entry.highlightBackground", input_bg)
        self.root.option_add("*Entry.highlightColor", button_outline)
        self.root.option_add("*Entry.insertBackground", text_insert_bg)
        
        # Fix for listbox and other widgets
        self.root.option_add("*Listbox.background", input_bg)
        self.root.option_add("*Listbox.foreground", fg_color)
        self.root.option_add("*Listbox.selectBackground", text_select_bg)
        self.root.option_add("*Listbox.selectForeground", text_select_fg)
        
        # Configure scrollbar colors
        self.root.option_add("*Scrollbar.troughColor", "#2D2D2D")
        self.root.option_add("*Scrollbar.background", "#3C3C3C")
        self.root.option_add("*Scrollbar.activeBackground", "#4D4D4D")
        self.root.option_add("*Scrollbar.highlightBackground", "#1E1E1E")
        self.root.option_add("*Scrollbar.highlightColor", "#1E1E1E")
        
    def _create_identifier_section(self):
        """Create the identifier input section"""
        section_frame = ttk.Frame(self.main_frame, style="Section.TFrame", padding=8)
        section_frame.pack(fill=tk.X, pady=4)
        
        ttk.Label(section_frame, text="License Identifier", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        # Type selection
        type_frame = ttk.Frame(section_frame)
        type_frame.pack(fill=tk.X, pady=4)
        
        ttk.Label(type_frame, text="Identifier Type:").pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Radiobutton(type_frame, text="MAC Address (Type A)", 
                        variable=self.identifier_type_var, value="mac").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(type_frame, text="Baseboard Serial (Type B)", 
                        variable=self.identifier_type_var, value="baseboard").pack(side=tk.LEFT, padx=10)
        
        # Identifier input
        id_frame = ttk.Frame(section_frame)
        id_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(id_frame, text="Identifier:").pack(side=tk.LEFT, padx=(0, 10))
        id_entry = ttk.Entry(id_frame, textvariable=self.identifier_var, width=50, style="Dark.TEntry")
        id_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Helper text
        helper_frame = ttk.Frame(section_frame)
        helper_frame.pack(fill=tk.X, pady=4)
        ttk.Label(helper_frame, text="Format: 00:1A:2B:3C:4D:5E (MAC) or alphanumeric string (Baseboard)",
                  foreground="#999999", font=("Arial", 9)).pack(anchor=tk.W)
        
    def _create_license_options_section(self):
        """Create the license options section"""
        section_frame = ttk.Frame(self.main_frame, style="Section.TFrame", padding=8)
        section_frame.pack(fill=tk.X, pady=4)
        
        ttk.Label(section_frame, text="License Options", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        # Device limit
        limit_frame = ttk.Frame(section_frame)
        limit_frame.pack(fill=tk.X, pady=4)
        
        ttk.Label(limit_frame, text="Device Limit:").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Spinbox(limit_frame, from_=1, to=100, width=5, textvariable=self.device_limit_var,
                   style="Dark.TSpinbox").pack(side=tk.LEFT)
        
        # Expiry
        expiry_frame = ttk.Frame(section_frame)
        expiry_frame.pack(fill=tk.X, pady=8)
        
        ttk.Checkbutton(expiry_frame, text="Has Expiry Date", variable=self.has_expiry_var,
                       command=self._toggle_date_picker).pack(side=tk.LEFT)
        
        self.date_frame = ttk.Frame(expiry_frame)
        self.date_frame.pack(side=tk.LEFT, padx=10)
        
        # Date picker will be created dynamically when checkbox is checked
        
    def _toggle_date_picker(self):
        """Toggle the date picker visibility based on checkbox state"""
        # Clear the current date frame
        for widget in self.date_frame.winfo_children():
            widget.destroy()
            
        if self.has_expiry_var.get():
            # Create date selection widgets using standard Tkinter
            ttk.Label(self.date_frame, text="Expiry Date:").pack(side=tk.LEFT, padx=(0, 5))
            
            # Year dropdown (current year + 10 years)
            current_year = datetime.now().year
            year_options = [str(current_year + i) for i in range(11)]
            year_dropdown = ttk.Combobox(self.date_frame, textvariable=self.year_var, 
                                         values=year_options, width=6, state="readonly",
                                         style="TCombobox")
            year_dropdown.pack(side=tk.LEFT, padx=2)
            
            ttk.Label(self.date_frame, text="-").pack(side=tk.LEFT)
            
            # Month dropdown
            month_options = [str(i).zfill(2) for i in range(1, 13)]
            month_dropdown = ttk.Combobox(self.date_frame, textvariable=self.month_var, 
                                          values=month_options, width=4, state="readonly",
                                          style="TCombobox")
            month_dropdown.pack(side=tk.LEFT, padx=2)
            
            ttk.Label(self.date_frame, text="-").pack(side=tk.LEFT)
            
            # Day dropdown
            day_options = [str(i).zfill(2) for i in range(1, 32)]
            day_dropdown = ttk.Combobox(self.date_frame, textvariable=self.day_var, 
                                        values=day_options, width=4, state="readonly",
                                        style="TCombobox")
            day_dropdown.pack(side=tk.LEFT, padx=2)
            
            # Update date when any dropdown changes
            year_dropdown.bind("<<ComboboxSelected>>", lambda e: self._update_expiry_date())
            month_dropdown.bind("<<ComboboxSelected>>", lambda e: self._update_expiry_date())
            day_dropdown.bind("<<ComboboxSelected>>", lambda e: self._update_expiry_date())
            
            # Set current selection to a year from now by default
            next_year = datetime.now() + timedelta(days=365)
            self.year_var.set(str(next_year.year))
            self.month_var.set(str(next_year.month).zfill(2))
            self.day_var.set(str(next_year.day).zfill(2))
            
            # Initialize expiry date
            self._update_expiry_date()
        else:
            self.expiry_date = None
    
    def _update_expiry_date(self):
        """Update the expiry date from the dropdown selections"""
        try:
            year = int(self.year_var.get())
            month = int(self.month_var.get())
            day = int(self.day_var.get())
            
            # Validate date
            if month > 12:
                month = 12
            
            # Adjust day based on month/year
            days_in_month = 31
            if month in [4, 6, 9, 11]:
                days_in_month = 30
            elif month == 2:
                # Check for leap year
                if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                    days_in_month = 29
                else:
                    days_in_month = 28
            
            if day > days_in_month:
                day = days_in_month
            
            # Format as YYYY-MM-DD
            self.expiry_date = f"{year}-{month:02d}-{day:02d}"
        except:
            # Default to a year from now if errors
            next_year = datetime.now() + timedelta(days=365)
            self.expiry_date = next_year.strftime("%Y-%m-%d")
    
    def _create_devices_section(self):
        """Create the registered devices section"""
        section_frame = ttk.Frame(self.main_frame, style="Section.TFrame", padding=8)
        section_frame.pack(fill=tk.BOTH, expand=False, pady=4)
        
        ttk.Label(section_frame, text="Registered Devices", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        # Add device controls
        add_frame = ttk.Frame(section_frame)
        add_frame.pack(fill=tk.X, pady=4)
        
        self.device_var = tk.StringVar()
        ttk.Label(add_frame, text="Device ID:").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Entry(add_frame, textvariable=self.device_var, width=40, style="Dark.TEntry").pack(side=tk.LEFT, padx=5)
        
        # Use custom dark button
        add_btn = tk.Button(add_frame, text="Add Device", 
                           command=self._add_device,
                           bg="#2D2D2D", fg="#E0E0E0",
                           activebackground="#3D3D3D",
                           activeforeground="#FFFFFF",
                           highlightbackground="#2D2D2D",
                           highlightcolor="#0D6EFD",
                           bd=1, relief="solid")
        add_btn.pack(side=tk.LEFT, padx=10)
        
        # Device list
        list_frame = ttk.Frame(section_frame)
        list_frame.pack(fill=tk.BOTH, expand=False, pady=5)
        
        # Create a frame with scrollbar for the devices list
        self.devices_list = scrolledtext.ScrolledText(list_frame, wrap=tk.WORD, height=5,
                                                      width=50, state=tk.DISABLED,
                                                      bg="#2D2D2D", fg="#E0E0E0",
                                                      insertbackground="#E0E0E0",
                                                      selectbackground="#0D6EFD",
                                                      selectforeground="#FFFFFF",
                                                      relief="solid", borderwidth=1)
        self.devices_list.pack(fill=tk.BOTH, expand=False)
        
        # Buttons for managing devices
        btn_frame = ttk.Frame(section_frame)
        btn_frame.pack(fill=tk.X, pady=4)
        
        # Create dark buttons with custom styling
        remove_btn = tk.Button(btn_frame, text="Remove Selected", 
                              command=self._remove_selected_device,
                              bg="#2D2D2D", fg="#E0E0E0",
                              activebackground="#3D3D3D",
                              activeforeground="#FFFFFF",
                              highlightbackground="#2D2D2D",
                              highlightcolor="#0D6EFD",
                              bd=1, relief="solid")
        remove_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_btn = tk.Button(btn_frame, text="Clear All", 
                             command=self._clear_devices,
                             bg="#2D2D2D", fg="#E0E0E0",
                             activebackground="#3D3D3D",
                             activeforeground="#FFFFFF",
                             highlightbackground="#2D2D2D",
                             highlightcolor="#0D6EFD",
                             bd=1, relief="solid")
        clear_btn.pack(side=tk.LEFT)
        
        use_id_btn = tk.Button(btn_frame, text="Use Identifier as Device", 
                              command=self._use_identifier_as_device,
                              bg="#2D2D2D", fg="#E0E0E0",
                              activebackground="#3D3D3D",
                              activeforeground="#FFFFFF",
                              highlightbackground="#2D2D2D",
                              highlightcolor="#0D6EFD",
                              bd=1, relief="solid")
        use_id_btn.pack(side=tk.LEFT, padx=10)
    
    def _add_device(self):
        """Add a device to the list"""
        device = self.device_var.get().strip()
        if not device:
            messagebox.showwarning("Input Error", "Please enter a device ID")
            return
            
        # Validate format based on identifier type
        if self.identifier_type_var.get() == "mac":
            # Simple MAC validation pattern
            pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            if not re.match(pattern, device):
                messagebox.showwarning("Format Error", "Invalid MAC address format. Use format: 00:1A:2B:3C:4D:5E")
                return
        
        if device not in self.registered_devices:
            self.registered_devices.append(device)
            self._update_devices_list()
            self.device_var.set("")  # Clear input field
        else:
            messagebox.showinfo("Duplicate", "This device is already in the list")
    
    def _update_devices_list(self):
        """Update the devices list display"""
        self.devices_list.config(state=tk.NORMAL)
        self.devices_list.delete(1.0, tk.END)
        
        for i, device in enumerate(self.registered_devices, 1):
            self.devices_list.insert(tk.END, f"{i}. {device}\n")
            
        self.devices_list.config(state=tk.DISABLED)
    
    def _remove_selected_device(self):
        """Remove the selected device from the list"""
        try:
            selection = self.devices_list.tag_ranges(tk.SEL)
            if selection:
                content = self.devices_list.get(selection[0], selection[1]).strip()
                # Extract device ID from the selected line
                for device in self.registered_devices:
                    if device in content:
                        self.registered_devices.remove(device)
                        self._update_devices_list()
                        break
        except:
            messagebox.showinfo("Selection", "Please select a device to remove")
    
    def _clear_devices(self):
        """Clear all devices from the list"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all devices?"):
            self.registered_devices = []
            self._update_devices_list()
    
    def _use_identifier_as_device(self):
        """Add the current identifier as a device"""
        identifier = self.identifier_var.get().strip()
        if not identifier:
            messagebox.showwarning("Input Error", "Please enter an identifier first")
            return
            
        if identifier not in self.registered_devices:
            self.registered_devices.append(identifier)
            self._update_devices_list()
        else:
            messagebox.showinfo("Duplicate", "This device is already in the list")
    
    def _create_output_section(self):
        """Create the output display section"""
        section_frame = ttk.Frame(self.main_frame, style="Section.TFrame", padding=8)
        section_frame.pack(fill=tk.X, pady=4)
        
        ttk.Label(section_frame, text="License Key Output", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        # Create output text area
        self.output_text = scrolledtext.ScrolledText(section_frame, wrap=tk.WORD, height=5,
                                                    width=80,
                                                    bg="#2D2D2D", fg="#E0E0E0",
                                                    insertbackground="#E0E0E0",
                                                    selectbackground="#0D6EFD",
                                                    selectforeground="#FFFFFF",
                                                    relief="solid", borderwidth=1)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=4)
        
    def _create_buttons_section(self):
        """Create the action buttons section"""
        btn_frame = ttk.Frame(self.main_frame, padding=8)
        btn_frame.pack(fill=tk.X, pady=8)
        
        # Use custom tk buttons for consistent dark theme
        gen_btn = tk.Button(btn_frame, text="Generate License Key", 
                           command=self.generate_license,
                           bg="#252525", fg="#E0E0E0",
                           activebackground="#353535",
                           activeforeground="#FFFFFF",
                           highlightbackground="#252525",
                           highlightcolor="#198754",
                           bd=1, relief="solid",
                           font=("Arial", 11, "bold"),
                           padx=6, pady=4)
        gen_btn.pack(side=tk.LEFT, padx=5)
        
        copy_btn = tk.Button(btn_frame, text="Copy Key", 
                            command=self._copy_key,
                            bg="#2D2D2D", fg="#E0E0E0",
                            activebackground="#3D3D3D",
                            activeforeground="#FFFFFF",
                            highlightbackground="#2D2D2D",
                            highlightcolor="#0D6EFD",
                            bd=1, relief="solid")
        copy_btn.pack(side=tk.LEFT, padx=5)
        
        save_btn = tk.Button(btn_frame, text="Save Key", 
                            command=self._save_key,
                            bg="#2D2D2D", fg="#E0E0E0",
                            activebackground="#3D3D3D",
                            activeforeground="#FFFFFF",
                            highlightbackground="#2D2D2D",
                            highlightcolor="#0D6EFD",
                            bd=1, relief="solid")
        save_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(btn_frame, text="Clear", 
                             command=self._clear_output,
                            bg="#2D2D2D", fg="#E0E0E0",
                            activebackground="#3D3D3D",
                            activeforeground="#FFFFFF",
                            highlightbackground="#2D2D2D",
                            highlightcolor="#0D6EFD",
                            bd=1, relief="solid")
        clear_btn.pack(side=tk.LEFT, padx=5)
    
    def _get_encryption_key(self) -> bytes:
        """
        Get the fixed encryption key used for all licenses.
        
        Returns:
            bytes: Fernet encryption key
        """
        # Use PBKDF2 to derive a key from the fixed password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=self.SALT,
            iterations=100000,  # Higher makes it more secure but slower
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.SECRET_PASSWORD))
        return key
    
    def generate_license(self):
        """Generate a license key based on the input parameters"""
        # Validate inputs
        identifier = self.identifier_var.get().strip()
        if not identifier:
            messagebox.showwarning("Input Error", "Please enter an identifier")
            return
            
        identifier_type = self.identifier_type_var.get()
        
        try:
            device_limit = int(self.device_limit_var.get())
            if device_limit <= 0:
                raise ValueError("Device limit must be positive")
        except ValueError:
            messagebox.showwarning("Input Error", "Please enter a valid device limit")
            return
        
        # Get expiry date if applicable
        expiry_date = self.expiry_date if self.has_expiry_var.get() else None
        
        # Generate the key
        self._clear_output()
        
        # Prepare key type
        key_type = 'A' if identifier_type == 'mac' else 'B'
        
        # Prepare license info data
        license_info = {
            'key_type': key_type,
            'identifier': identifier,
            'expiry_date': expiry_date if expiry_date else 'None',
            'device_limit': device_limit,
            'registered_devices': self.registered_devices
        }
        
        # Get fixed encryption key
        encryption_key = self._get_encryption_key()
        
        # Create Fernet cipher with this key
        cipher = Fernet(encryption_key)
        
        # Encrypt the license data
        license_json = json.dumps(license_info)
        encrypted_license = cipher.encrypt(license_json.encode())
        
        # Convert to string for storage
        encrypted_license_str = encrypted_license.decode()
        
        # Add license key to the info for storage in license_info.json
        license_info['license_key'] = encrypted_license_str
        
        # Display the output
        self.output_text.insert(tk.END, f"License Type: {'MAC Address (A)' if key_type == 'A' else 'Baseboard Serial (B)'}\n")
        self.output_text.insert(tk.END, f"Identifier: {identifier}\n")
        self.output_text.insert(tk.END, f"Device Limit: {device_limit}\n")
        self.output_text.insert(tk.END, f"Expiry Date: {expiry_date if expiry_date else 'Never (Lifetime)'}\n")
        self.output_text.insert(tk.END, f"Registered Devices: {len(self.registered_devices)}\n\n")
        
        # Show the encrypted license key
        self.output_text.insert(tk.END, f"ENCRYPTED LICENSE KEY:\n{encrypted_license_str}\n")
        
        # Save to files
        try:
            with open('license_info.json', 'w') as f:
                json.dump(license_info, f, indent=4)
                
            with open('.key', 'w') as f:
                f.write(encrypted_license_str)
                
            self.output_text.insert(tk.END, "\nLicense files saved:\n")
            self.output_text.insert(tk.END, f"- license_info.json (for management only)\n")
            self.output_text.insert(tk.END, f"- .key (for distribution to clients)\n")
            
            self.output_text.insert(tk.END, "\nNOTE: Only distribute the .key file to clients. The license_info.json file is for your records only.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\nError saving license files: {str(e)}\n")
    
    def _copy_key(self):
        """Copy the generated key to clipboard"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.output_text.get(1.0, tk.END))
            messagebox.showinfo("Success", "License key information copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Could not copy to clipboard: {str(e)}")
    
    def _save_key(self):
        """Save the license key to a custom file"""
        try:
            # Check if there's content to save
            content = self.output_text.get(1.0, tk.END).strip()
            if not content:
                messagebox.showwarning("Warning", "No license key to save")
                return
                
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save License Key As"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"License key saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file: {str(e)}")
    
    def _clear_output(self):
        """Clear the output text area"""
        self.output_text.delete(1.0, tk.END)

def main():
    root = tk.Tk()
    app = LicenseManagerApp(root)
    
    # Apply dark theme colors to tk widgets as well
    root.configure(bg="#1E1E1E")
    
    # Configure scrollbar colors for all scrolled texts
    root.option_add("*Scrollbar.troughColor", "#2D2D2D")
    root.option_add("*Scrollbar.background", "#3C3C3C")
    root.option_add("*Scrollbar.activeBackground", "#4D4D4D")
    root.option_add("*Scrollbar.highlightBackground", "#1E1E1E")
    root.option_add("*Scrollbar.highlightColor", "#1E1E1E")
    
    for widget in root.winfo_children():
        if isinstance(widget, tk.Frame):
            widget.configure(bg="#1E1E1E")
    
    root.mainloop()

if __name__ == "__main__":
    main() 