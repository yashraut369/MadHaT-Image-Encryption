import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import io
import os
import base64
import time
import threading
import random
from typing import Optional, Tuple, List

# Crypto imports
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# ================ MADHAT THEME CONFIG ================ #
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class HackerTheme:
    """MadHat Hacker Theme Configuration"""
    PRIMARY = "#0A0A0A"  # Main background
    SECONDARY = "#121212"  # Secondary background
    ACCENT = "#39FF14"  # Neon green accent
    ACCENT_RED = "#FF3333"  # Red accent
    ACCENT_BLUE = "#00FFFF"  # Cyan accent
    
    BUTTON_BG = "#1A1F1C"
    BUTTON_HOVER = "#2A332D"
    
    ENCRYPT_BTN = "#1A4D2E"
    ENCRYPT_HOVER = "#2B6049"
    
    DECRYPT_BTN = "#4D1A1A"
    DECRYPT_HOVER = "#602B2B"
    
    @staticmethod
    def get_random_neon_color():
        colors = ["#39FF14", "#00FFFF", "#FF00FF", "#FF355E", "#FF9933", "#FFFF00"]
        return random.choice(colors)

# ================ CUSTOM WIDGETS ================ #
class HackerButton(ctk.CTkButton):
    """Custom styled button for the hacker theme"""
    def __init__(self, *args, **kwargs):
        border_width = kwargs.pop("border_width", 2)
        border_color = kwargs.pop("border_color", HackerTheme.ACCENT)
        text_color = kwargs.pop("text_color", HackerTheme.ACCENT)
        
        super().__init__(
            *args,
            border_width=border_width,
            border_color=border_color,
            text_color=text_color,
            **kwargs
        )

class TypewriterLabel(ctk.CTkLabel):
    """Label with typewriter animation effect"""
    def __init__(self, *args, **kwargs):
        self.typewriter_speed = kwargs.pop("typewriter_speed", 50)  # ms
        self.typewriter_text = kwargs.pop("text", "")
        kwargs["text"] = ""
        
        super().__init__(*args, **kwargs)
        
        if self.typewriter_text:
            self.start_typewriter(self.typewriter_text)
    
    def start_typewriter(self, text):
        self.typewriter_text = text
        self.current_char = 0
        self.typewriter_update()
    
    def typewriter_update(self):
        if self.current_char <= len(self.typewriter_text):
            self.configure(text=self.typewriter_text[:self.current_char])
            self.current_char += 1
            self.after(self.typewriter_speed, self.typewriter_update)

class HackerProgressBar(ctk.CTkProgressBar):
    """Custom styled progress bar with animations"""
    def __init__(self, *args, **kwargs):
        progress_color = kwargs.pop("progress_color", HackerTheme.ACCENT)
        
        super().__init__(
            *args,
            progress_color=progress_color,
            **kwargs
        )
        self.set(0)
        
    def simulate_progress(self, duration=2.0, callback=None):
        """Simulates a progress animation over specified duration"""
        thread = threading.Thread(target=self._progress_thread, args=(duration, callback))
        thread.daemon = True
        thread.start()
    
    def _progress_thread(self, duration, callback):
        steps = 50
        for i in range(steps + 1):
            progress = i / steps
            time.sleep(duration / steps)
            ctk.CTk.after(self.master, 0, self.set, progress)
        
        if callback:
            ctk.CTk.after(self.master, 0, callback)

class HexagonView(ctk.CTkCanvas):
    """Custom hexagon grid visualization widget"""
    def __init__(self, master, width=200, height=200, hex_size=20, **kwargs):
        super().__init__(master, width=width, height=height, 
                         bg=kwargs.get("bg", "#0A0A0A"), 
                         highlightthickness=0)
        
        self.width = width
        self.height = height
        self.hex_size = hex_size
        self.hexagons = []
        self._generate_grid()
        
        self.animate_cycle = 0
        self.active = True
        self.animate()
    
    def _generate_grid(self):
        vert_dist = self.hex_size * 1.5
        horiz_dist = self.hex_size * 1.732  # sqrt(3) * size
        
        rows = int(self.height / vert_dist) + 2
        cols = int(self.width / horiz_dist) + 2
        
        for row in range(rows):
            for col in range(cols):
                x = col * horiz_dist
                y = row * vert_dist
                
                # Offset even rows
                if row % 2 == 0:
                    x += horiz_dist / 2
                
                if 0 <= x <= self.width + self.hex_size and 0 <= y <= self.height + self.hex_size:
                    self.hexagons.append((x, y))
    
    def draw_hexagon(self, x, y, size, outline_color, fill_color=None, width=1):
        # Calculate the six points of the hexagon
        points = []
        for i in range(6):
            angle_deg = 60 * i - 30
            angle_rad = 3.14159 / 180 * angle_deg
            point_x = x + size * 0.866 * 2 * 0.5 * 0.9 * (0.5 + 0.5 * 1 * (0.5 + 0.5 * (-1) ** (i % 2)))
            point_y = y + size * 0.5 * 1.732 * 0.9 * (0.5 + 0.5 * (-1) ** (i // 2))
            points.append(point_x)
            points.append(point_y)
        
        return self.create_polygon(points, outline=outline_color, fill=fill_color if fill_color else "", width=width)
    
    def animate(self):
        if not self.active:
            return
            
        self.delete("all")
        
        # Modulate animation cycle
        self.animate_cycle = (self.animate_cycle + 1) % 120
        
        # Draw grid with animation effects
        for i, (x, y) in enumerate(self.hexagons):
            # Create different visual patterns
            phase_offset = (x + y) / 30
            pulse = 0.5 + 0.5 * (1 + 0.8 * (i % 3)) * (0.5 + 0.5 * (-1) ** (i % 4))
            color_intensity = (127 + 128 * pulse) * (0.2 + 0.8 * ((0.5 + 0.5 * (-1) ** i) + 0.5))
            
            # Different color patterns
            if (i + self.animate_cycle // 10) % 5 == 0:
                color = HackerTheme.ACCENT
                width = 2
            else:
                green_val = int(color_intensity) % 256
                # Create a darker green
                color = f"#{0:02x}{green_val//3:02x}{0:02x}"
                width = 1
                
            self.draw_hexagon(x, y, self.hex_size, outline_color=color, width=width)
        
        self.after(50, self.animate)
    
    def stop_animation(self):
        self.active = False

class ConsoleOutput(ctk.CTkTextbox):
    """Console-like output display with terminal styling"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT,
            fg_color="#0A0A0A",
            border_width=1,
            border_color="#333333",
            state="disabled"
        )
        self.tag_config("error", foreground=HackerTheme.ACCENT_RED)
        self.tag_config("success", foreground=HackerTheme.ACCENT)
        self.tag_config("info", foreground=HackerTheme.ACCENT_BLUE)
    
    def log(self, message, tag=None):
        self.configure(state="normal")
        if tag:
            self.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
        else:
            self.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.configure(state="disabled")
        self.see("end")

class AnimatedLogo(ctk.CTkCanvas):
    """Animated MadHat logo with custom effects"""
    def __init__(self, master, size=100, **kwargs):
        super().__init__(master, width=size, height=size, 
                         bg=kwargs.get("bg", "#0A0A0A"), 
                         highlightthickness=0)
        
        self.size = size
        self.angle = 0
        self.active = True
        self.draw_logo()
        self.animate()
    
    def draw_logo(self):
        self.delete("all")
        
        # Center coordinates
        cx, cy = self.size / 2, self.size / 2
        
        # Draw outer ring
        self.create_oval(10, 10, self.size-10, self.size-10, 
                         outline=HackerTheme.ACCENT, width=2)
        
        # Draw M letter with animation
        points = []
        for i in range(5):
            angle = 2.0 * 3.14159 * (i / 5) + self.angle
            r = self.size * 0.35
            x = cx + r * 0.8 * 1.2 * (0.5 + 0.5 * (-1) ** (i % 2)) * 0.8
            y = cy + r * 1.732 * 0.8 * (0.5 + 0.5 * (-1) ** (i // 2)) * 0.8
            points.extend([x, y])
        
        self.create_polygon(points, fill="", outline=HackerTheme.ACCENT, width=2)
        
        # Draw inner circle with pulse effect
        pulse = (0.5 + 0.5 * (0.5 + 0.5 * (-1) ** int(self.angle * 5)))
        inner_size = self.size * 0.2 * pulse
        self.create_oval(cx - inner_size, cy - inner_size, 
                         cx + inner_size, cy + inner_size,
                         fill=HackerTheme.ACCENT, outline="")
    
    def animate(self):
        if not self.active:
            return
            
        self.angle = (self.angle + 0.05) % (2 * 3.14159)
        self.draw_logo()
        self.after(50, self.animate)
    
    def stop_animation(self):
        self.active = False

# ================ ENCRYPTION UTILITIES ================ #
class CryptoEngine:
    """Handles all cryptographic operations"""
    
    ALGORITHMS = {
        "AES-256-CBC": "AES-256 (CBC Mode)",
        "AES-256-GCM": "AES-256 (GCM Mode)", 
        "ChaCha20": "ChaCha20",
        "XChaCha20": "XChaCha20 (Extended Nonce)"
    }
    
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
        """Derive a key from password using PBKDF2"""
        return PBKDF2(password.encode(), salt, dkLen=32, count=iterations, 
                      hmac_hash_module=SHA256)
    
    @staticmethod
    def generate_file_hash(data: bytes) -> str:
        """Generate a hash of file data"""
        return SHA256.new(data).hexdigest()[:16]
    
    @staticmethod
    def encrypt_file(data: bytes, password: str, algorithm: str) -> Tuple[bytes, dict]:
        """
        Encrypt file data with the selected algorithm
        Returns encrypted data and metadata
        """
        salt = get_random_bytes(16)
        key = CryptoEngine.derive_key(password, salt)
        metadata = {
            "salt": salt,
            "algorithm": algorithm,
            "version": "1.0",
            "created": int(time.time()),
            "original_hash": CryptoEngine.generate_file_hash(data)
        }
        
        if algorithm == "AES-256-CBC":
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_data = cipher.encrypt(pad(data, AES.block_size))
            metadata["iv"] = iv
            
        elif algorithm == "AES-256-GCM":
            nonce = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            encrypted_data, tag = cipher.encrypt_and_digest(data)
            metadata["nonce"] = nonce
            metadata["tag"] = tag
            
        elif algorithm == "ChaCha20":
            nonce = get_random_bytes(8)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            encrypted_data = cipher.encrypt(data)
            metadata["nonce"] = nonce
            
        elif algorithm == "XChaCha20":
            # XChaCha20 implementation would go here
            # For now we'll use ChaCha20 with a larger nonce
            nonce = get_random_bytes(16)
            cipher = ChaCha20.new(key=key, nonce=nonce[:8])
            encrypted_data = cipher.encrypt(data)
            metadata["nonce"] = nonce
        
        return encrypted_data, metadata
    
    @staticmethod
    def decrypt_file(encrypted_data: bytes, metadata: dict, password: str) -> bytes:
        """
        Decrypt file data using metadata and password
        """
        salt = metadata["salt"]
        algorithm = metadata["algorithm"]
        key = CryptoEngine.derive_key(password, salt)
        
        if algorithm == "AES-256-CBC":
            iv = metadata["iv"]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
        elif algorithm == "AES-256-GCM":
            nonce = metadata["nonce"]
            tag = metadata["tag"]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(encrypted_data, tag)
            
        elif algorithm == "ChaCha20":
            nonce = metadata["nonce"]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            return cipher.decrypt(encrypted_data)
            
        elif algorithm == "XChaCha20":
            # XChaCha20 implementation would go here
            # For now we'll use ChaCha20 with a larger nonce
            nonce = metadata["nonce"]
            cipher = ChaCha20.new(key=key, nonce=nonce[:8])
            return cipher.decrypt(encrypted_data)
        
        raise ValueError(f"Unsupported algorithm: {algorithm}")

# ================ MAIN APPLICATION ================ #
class MadHatPixelEncryptor(ctk.CTk):
    """Main application window for MadHat Pixel Encryptor"""
    
    def __init__(self):
        super().__init__()
        self.title("MadHaT Pixel Encryptor v2.0 - by Popeye")
        self.geometry("1024x768")
        self.configure(fg_color=HackerTheme.PRIMARY)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # App state
        self.current_file = None
        self.current_file_type = None
        self.current_image = None
        self.encrypting = False
        self.decrypting = False
        
        # Initialize UI components
        self.create_header()
        self.create_main_interface()
        self.create_footer()
        
        # Startup animation
        self.after(100, self.startup_sequence)
        
        # Bind ESC key to quit
        self.bind("<Escape>", lambda e: self.quit())
    
    def create_header(self):
        """Create the header section with logo and title"""
        header_frame = ctk.CTkFrame(self, corner_radius=0, 
                                   fg_color=HackerTheme.SECONDARY, 
                                   height=80)
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(1, weight=1)
        
        # Logo
        self.logo = AnimatedLogo(header_frame, size=60)
        self.logo.grid(row=0, column=0, padx=20, pady=10)
        
        # Title with typewriter effect
        self.title_label = TypewriterLabel(
            header_frame,
            text="⚡ MADHAT PIXEL ENCRYPTOR v2.0 ⚡",
            font=("Courier New", 24, "bold"),
            text_color=HackerTheme.ACCENT,
            typewriter_speed=25
        )
        self.title_label.grid(row=0, column=1, padx=20, pady=10)
        
        # Current time
        self.time_label = ctk.CTkLabel(
            header_frame,
            text=time.strftime("%H:%M:%S"),
            font=("Courier New", 16),
            text_color=HackerTheme.ACCENT
        )
        self.time_label.grid(row=0, column=2, padx=20, pady=10)
        
        # Update time every second
        self.update_time()
    
    def update_time(self):
        """Update the time display"""
        self.time_label.configure(text=time.strftime("%H:%M:%S"))
        self.after(1000, self.update_time)
    
    def create_main_interface(self):
        """Create the main interface with panels"""
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=3)
        main_frame.grid_rowconfigure(0, weight=1)
        
        # Left control panel
        self.create_control_panel(main_frame)
        
        # Right content panel
        self.create_content_panel(main_frame)
    
    def create_control_panel(self, parent):
        """Create the left control panel with encryption options"""
        control_frame = ctk.CTkFrame(parent, corner_radius=10, 
                                    fg_color=HackerTheme.SECONDARY)
        control_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=0)
        control_frame.grid_columnconfigure(0, weight=1)
        
        # Panel title
        ctk.CTkLabel(control_frame, 
                    text="CONTROL PANEL",
                    font=("Courier New", 16, "bold"),
                    text_color=HackerTheme.ACCENT).pack(pady=(20, 10))
        
        # File selection
        self.file_button = HackerButton(
            control_frame,
            text="SELECT FILE",
            command=self.load_file,
            fg_color=HackerTheme.BUTTON_BG,
            hover_color=HackerTheme.BUTTON_HOVER,
            font=("Courier New", 14)
        )
        self.file_button.pack(pady=10, padx=20, fill="x")
        
        # Selected file info
        self.file_info = ctk.CTkLabel(
            control_frame,
            text="No file selected",
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT,
            wraplength=200
        )
        self.file_info.pack(pady=5)
        
        # Separator
        self.create_separator(control_frame)
        
        # Password entry
        ctk.CTkLabel(control_frame, 
                    text="ENCRYPTION KEY",
                    font=("Courier New", 14),
                    text_color=HackerTheme.ACCENT).pack(pady=(10, 5))
        
        self.pwd_entry = ctk.CTkEntry(
            control_frame,
            show="●",
            font=("Courier New", 14),
            border_color=HackerTheme.ACCENT,
            text_color=HackerTheme.ACCENT
        )
        self.pwd_entry.pack(pady=5, padx=20, fill="x")
        
        # Password strength meter
        self.pwd_strength_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        self.pwd_strength_frame.pack(pady=5, padx=20, fill="x")
        
        self.pwd_strength_label = ctk.CTkLabel(
            self.pwd_strength_frame,
            text="Strength: N/A",
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT
        )
        self.pwd_strength_label.pack(side="top", anchor="w")
        
        self.pwd_strength_bar = HackerProgressBar(self.pwd_strength_frame)
        self.pwd_strength_bar.pack(side="top", fill="x", pady=(3, 0))
        
        # Bind password change event
        self.pwd_entry.bind("<KeyRelease>", self.update_password_strength)
        
        # Separator
        self.create_separator(control_frame)
        
        # Algorithm selection
        ctk.CTkLabel(control_frame, 
                    text="ALGORITHM",
                    font=("Courier New", 14),
                    text_color=HackerTheme.ACCENT).pack(pady=(10, 5))
        
        self.algo_var = ctk.StringVar(value="AES-256-CBC")
        self.algo_menu = ctk.CTkOptionMenu(
            control_frame,
            values=list(CryptoEngine.ALGORITHMS.values()),
            variable=self.algo_var,
            fg_color=HackerTheme.BUTTON_BG,
            button_color=HackerTheme.BUTTON_BG,
            button_hover_color=HackerTheme.BUTTON_HOVER,
            dropdown_fg_color=HackerTheme.BUTTON_BG,
            dropdown_hover_color=HackerTheme.BUTTON_HOVER,
            text_color=HackerTheme.ACCENT,
            font=("Courier New", 14)
        )
        self.algo_menu.pack(pady=5, padx=20, fill="x")
        
        # Algorithm description
        self.algo_description = ctk.CTkLabel(
            control_frame,
            text="Advanced Encryption Standard\nwith 256-bit key in CBC mode",
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT,
            justify="left",
            wraplength=200
        )
        self.algo_description.pack(pady=5, padx=20, fill="x")
        
        # Update description when algorithm changes
        self.algo_var.trace_add("write", self.update_algorithm_description)
        
        # Separator
        self.create_separator(control_frame)
        
        # Action buttons
        action_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        action_frame.pack(pady=15, padx=20, fill="x")
        
        self.encrypt_btn = HackerButton(
            action_frame,
            text="ENCRYPT",
            command=self.encrypt_file,
            fg_color=HackerTheme.ENCRYPT_BTN,
            hover_color=HackerTheme.ENCRYPT_HOVER,
            border_color=HackerTheme.ACCENT,
            font=("Courier New", 14)
        )
        self.encrypt_btn.pack(side="left", expand=True, fill="x", padx=(0, 5))
        
        self.decrypt_btn = HackerButton(
            action_frame,
            text="DECRYPT",
            command=self.decrypt_file,
            fg_color=HackerTheme.DECRYPT_BTN,
            hover_color=HackerTheme.DECRYPT_HOVER,
            border_color=HackerTheme.ACCENT_RED,
            text_color=HackerTheme.ACCENT_RED,
            font=("Courier New", 14)
        )
        self.decrypt_btn.pack(side="right", expand=True, fill="x", padx=(5, 0))
        
        # Hexagon background at the bottom
        hex_view = HexagonView(control_frame, height=120)
        hex_view.pack(side="bottom", fill="x", pady=10)
    
    def create_content_panel(self, parent):
        """Create the right content panel with image preview and console"""
        content_frame = ctk.CTkFrame(parent, corner_radius=10, 
                                    fg_color=HackerTheme.SECONDARY)
        content_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=0)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(0, weight=3)
        content_frame.grid_rowconfigure(1, weight=1)
        
        # Image preview panel
        preview_frame = ctk.CTkFrame(content_frame, fg_color="#080808", corner_radius=5)
        preview_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        preview_frame.grid_columnconfigure(0, weight=1)
        preview_frame.grid_rowconfigure(0, weight=1)
        
        # Preview label
        self.preview_label = ctk.CTkLabel(
            preview_frame,
            text="No image to preview",
            font=("Courier New", 16),
            text_color=HackerTheme.ACCENT
        )
        self.preview_label.grid(row=0, column=0, sticky="nsew")
        
        # Console panel
        console_frame = ctk.CTkFrame(content_frame, fg_color="#080808", corner_radius=5)
        console_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        console_frame.grid_columnconfigure(0, weight=1)
        console_frame.grid_rowconfigure(0, weight=1)
        
        # Console header
        console_header = ctk.CTkFrame(console_frame, fg_color="#121212", height=30, corner_radius=0)
        console_header.pack(fill="x")
        
        ctk.CTkLabel(
            console_header,
            text="SYSTEM CONSOLE",
            font=("Courier New", 12, "bold"),
            text_color=HackerTheme.ACCENT
        ).pack(side="left", padx=10)
        
        # Console output
        self.console = ConsoleOutput(console_frame)
        self.console.pack(fill="both", expand=True, padx=5, pady=(0, 5))
    
    def create_separator(self, parent):
        """Create a separator line"""
        sep = ctk.CTkFrame(parent, height=1, fg_color=HackerTheme.ACCENT)
        sep.pack(fill="x", padx=20, pady=10)
    
    def create_footer(self):
        """Create the footer with status information"""
        footer_frame = ctk.CTkFrame(self, corner_radius=0, 
                                   fg_color=HackerTheme.SECONDARY, 
                                   height=30)
        footer_frame.grid(row=2, column=0, sticky="ew")
        footer_frame.grid_columnconfigure(1, weight=1)
        
        # Status indicator
        self.status_indicator = ctk.CTkFrame(
            footer_frame, 
            width=16, 
            height=16, 
            corner_radius=8,
            fg_color=HackerTheme.ACCENT
        )
        self.status_indicator.grid(row=0, column=0, padx=10, pady=7)
        
        # Status text
        self.status_text = ctk.CTkLabel(
            footer_frame,
            text="READY",
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT
        )
        self.status_text.grid(row=0, column=1, sticky="w")
        
        # Version info
        ctk.CTkLabel(
            footer_frame,
            text="MadHaT Security v2.0 | Popeye",
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT
        ).grid(row=0, column=2, padx=10)
        
        # Start status blinking
        self.blink_status()
    
    def blink_status(self):
        """Animated blinking for the status indicator"""
        if hasattr(self, "blink_state") and self.blink_state:
            color = HackerTheme.ACCENT
            delay = 800
        else:
            color = "#0A0A0A"
            delay = 800
        
        self.blink_state = not getattr(self, "blink_state", False)
        self.status_indicator.configure(fg_color=color)
        self.after(delay, self.blink_status)
    
    def startup_sequence(self):
        """Run startup animation sequence"""
        self.console.log("System initializing...", "info")
        self.after(200, lambda: self.console.log("Loading cryptographic modules..."))
        self.after(400, lambda: self.console.log("Loading cryptographic modules..."))
        self.after(600, lambda: self.console.log("Initializing UI components..."))
        self.after(800, lambda: self.console.log("Checking system security..."))
        self.after(1000, lambda: self.console.log("MadHat Pixel Encryptor ready!", "success"))
    
    def update_password_strength(self, event=None):
        """Update password strength indicator"""
        password = self.pwd_entry.get()
        
        if not password:
            strength = 0
            text = "Strength: N/A"
            color = "#555555"
        else:
            # Calculate password strength
            length_score = min(len(password) / 12, 1.0) * 0.4
            has_lower = any(c.islower() for c in password) * 0.15
            has_upper = any(c.isupper() for c in password) * 0.15
            has_digit = any(c.isdigit() for c in password) * 0.15
            has_special = any(not c.isalnum() for c in password) * 0.15
            
            strength = length_score + has_lower + has_upper + has_digit + has_special
            
            if strength < 0.3:
                text = "Strength: WEAK"
                color = HackerTheme.ACCENT_RED
            elif strength < 0.6:
                text = "Strength: MEDIUM"
                color = "#FFAA00"
            else:
                text = "Strength: STRONG"
                color = HackerTheme.ACCENT
        
        self.pwd_strength_label.configure(text=text)
        self.pwd_strength_bar.set(strength)
        self.pwd_strength_bar.configure(progress_color=color)
    
    def update_algorithm_description(self, *args):
        """Update the algorithm description when selection changes"""
        selected = self.algo_var.get()
        
        # Get the algorithm key from the display name
        algo_key = next((k for k, v in CryptoEngine.ALGORITHMS.items() if v == selected), None)
        
        if algo_key == "AES-256-CBC":
            desc = "Advanced Encryption Standard\nwith 256-bit key in CBC mode"
        elif algo_key == "AES-256-GCM":
            desc = "AES with Galois/Counter Mode\nAuthenticated encryption"
        elif algo_key == "ChaCha20":
            desc = "Stream cipher optimized for\nhigh performance on software"
        elif algo_key == "XChaCha20":
            desc = "Extended nonce variant of\nChaCha20 for added security"
        else:
            desc = "Select an algorithm"
        
        self.algo_description.configure(text=desc)
    
    def load_file(self):
        """Open file dialog and load selected file"""
        filetypes = [
            ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
            ("Encrypted files", "*.mhcrypt"),
            ("All files", "*.*")
        ]
        
        filepath = filedialog.askopenfilename(
            title="Select File to Encrypt/Decrypt",
            filetypes=filetypes
        )
        
        if not filepath:
            return
        
        self.current_file = filepath
        filename = os.path.basename(filepath)
        
        # Update UI with file info
        if filepath.lower().endswith('.mhcrypt'):
            self.current_file_type = "encrypted"
            self.file_info.configure(text=f"Encrypted file:\n{filename}")
            self.console.log(f"Loaded encrypted file: {filename}")
            self.update_status("READY TO DECRYPT")
        else:
            self.current_file_type = "image"
            self.file_info.configure(text=f"Image file:\n{filename}")
            self.console.log(f"Loaded image: {filename}")
            self.update_status("READY TO ENCRYPT")
        
        # Try to load and preview image
        self.load_preview(filepath)
    
    def load_preview(self, filepath):
        """Load and display image preview"""
        try:
            if filepath.lower().endswith('.mhcrypt'):
                # For encrypted files, show placeholder
                self.preview_label.configure(text="[ENCRYPTED CONTENT]")
                self.current_image = None
            else:
                # For images, show preview
                image = Image.open(filepath)
                self.current_image = image
                
                # Resize image for preview while maintaining aspect ratio
                preview_width = 500
                preview_height = 400
                image.thumbnail((preview_width, preview_height))
                
                # Convert to PhotoImage for display
                photo = ImageTk.PhotoImage(image)
                
                # Update preview
                self.preview_label.configure(text="")
                self.preview_label.configure(image=photo)
                self.preview_label.image = photo  # Keep a reference
                
                # Log image info
                self.console.log(f"Image dimensions: {image.width}x{image.height}", "info")
                
        except Exception as e:
            self.preview_label.configure(text="Preview not available")
            self.console.log(f"Error loading preview: {str(e)}", "error")
            self.current_image = None
    
    def update_status(self, text, blink=True):
        """Update status text in the footer"""
        self.status_text.configure(text=text)
    
    def encrypt_file(self):
        """Handle the encryption process"""
        if self.encrypting or self.decrypting:
            return  # Prevent multiple operations
        
        if not self.current_file or self.current_file_type != "image":
            messagebox.showerror("Error", "Please select an image file to encrypt")
            return
        
        password = self.pwd_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter an encryption key")
            return
        
        # Get selected algorithm key
        selected_algo_display = self.algo_var.get()
        algorithm = next((k for k, v in CryptoEngine.ALGORITHMS.items() if v == selected_algo_display), "AES-256-CBC")
        
        # Start encryption process
        self.encrypting = True
        self.update_status("ENCRYPTING...")
        self.console.log(f"Starting encryption with {selected_algo_display}...")
        
        # Show progress bar
        self.show_progress("Encrypting file...", callback=lambda: self.perform_encryption(password, algorithm))
    
    def perform_encryption(self, password, algorithm):
        """Perform actual encryption in a separate thread"""
        threading.Thread(target=self._encryption_thread, args=(password, algorithm)).start()
    
    def _encryption_thread(self, password, algorithm):
        """Thread function for encryption process"""
        try:
            # Read file data
            with open(self.current_file, "rb") as f:
                file_data = f.read()
            
            # Log original file info
            file_size = len(file_data) / 1024  # KB
            self.console.log(f"Original file size: {file_size:.2f} KB")
            
            # Encrypt data
            encrypted_data, metadata = CryptoEngine.encrypt_file(file_data, password, algorithm)
            
            # Create output filename
            original_filename = os.path.basename(self.current_file)
            output_dir = os.path.dirname(self.current_file)
            output_filename = f"{os.path.splitext(original_filename)[0]}.mhcrypt"
            output_path = os.path.join(output_dir, output_filename)
            
            # Format metadata as JSON-like bytes
            metadata_bytes = str(metadata).encode()
            
            # Write encrypted file with header
            with open(output_path, "wb") as f:
                # Write format identifier and version
                f.write(b"MADHAT")
                # Write metadata length as 4 bytes
                f.write(len(metadata_bytes).to_bytes(4, byteorder="big"))
                # Write metadata
                f.write(metadata_bytes)
                # Write encrypted data
                f.write(encrypted_data)
            
            # Log completion
            encrypted_size = os.path.getsize(output_path) / 1024  # KB
            self.console.log(f"Encryption complete!", "success")
            self.console.log(f"Encrypted file size: {encrypted_size:.2f} KB")
            self.console.log(f"Encrypted file saved to: {output_filename}")
            
            # Update UI
            self.after(0, lambda: self.encryption_completed(output_path))
            
        except Exception as e:
            self.console.log(f"Encryption error: {str(e)}", "error")
            self.after(0, lambda: self.encryption_failed(str(e)))
    
    def encryption_completed(self, output_path):
        """Called when encryption is complete"""
        self.encrypting = False
        self.update_status("ENCRYPTION COMPLETE")
        
        # Ask if user wants to open the encrypted file
        if messagebox.askyesno("Encryption Complete", 
                              f"File encrypted successfully!\n\nDo you want to load the encrypted file?"):
            self.current_file = output_path
            self.current_file_type = "encrypted"
            self.file_info.configure(text=f"Encrypted file:\n{os.path.basename(output_path)}")
            self.preview_label.configure(text="[ENCRYPTED CONTENT]", image="")
            self.update_status("READY TO DECRYPT")
    
    def encryption_failed(self, error_message):
        """Called when encryption fails"""
        self.encrypting = False
        self.update_status("ENCRYPTION FAILED")
        messagebox.showerror("Encryption Failed", f"Error during encryption:\n{error_message}")
    
    def decrypt_file(self):
        """Handle the decryption process"""
        if self.encrypting or self.decrypting:
            return  # Prevent multiple operations
        
        if not self.current_file or self.current_file_type != "encrypted":
            messagebox.showerror("Error", "Please select an encrypted file (.mhcrypt)")
            return
        
        password = self.pwd_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter the decryption key")
            return
        
        # Start decryption process
        self.decrypting = True
        self.update_status("DECRYPTING...")
        self.console.log("Starting decryption process...")
        
        # Show progress bar
        self.show_progress("Decrypting file...", callback=lambda: self.perform_decryption(password))
    
    def perform_decryption(self, password):
        """Perform actual decryption in a separate thread"""
        threading.Thread(target=self._decryption_thread, args=(password,)).start()
    
    def _decryption_thread(self, password):
        """Thread function for decryption process"""
        try:
            # Read encrypted file
            with open(self.current_file, "rb") as f:
                # Read header
                header = f.read(6)
                if header != b"MADHAT":
                    raise ValueError("Invalid file format or not a MadHat encrypted file")
                
                # Read metadata length
                meta_len_bytes = f.read(4)
                meta_len = int.from_bytes(meta_len_bytes, byteorder="big")
                
                # Read metadata
                meta_bytes = f.read(meta_len)
                metadata = eval(meta_bytes.decode())  # Convert string representation back to dict
                
                # Read encrypted data
                encrypted_data = f.read()
            
            # Log metadata info
            self.console.log(f"Algorithm: {metadata['algorithm']}")
            self.console.log(f"File created: {time.ctime(metadata['created'])}")
            
            # Decrypt data
            decrypted_data = CryptoEngine.decrypt_file(encrypted_data, metadata, password)
            
            # Verify file hash
            if metadata.get('original_hash'):
                current_hash = CryptoEngine.generate_file_hash(decrypted_data)
                if current_hash != metadata['original_hash']:
                    self.console.log("Warning: File hash verification failed!", "error")
            
            # Create output filename
            original_filename = os.path.basename(self.current_file)
            output_dir = os.path.dirname(self.current_file)
            
            # Try to determine original extension, default to .png
            extension = ".png"
            try:
                # Try to identify file type from magic numbers
                if decrypted_data.startswith(b'\x89PNG'):
                    extension = '.png'
                elif decrypted_data.startswith(b'\xff\xd8'):
                    extension = '.jpg'
                elif decrypted_data.startswith(b'GIF'):
                    extension = '.gif'
                elif decrypted_data.startswith(b'BM'):
                    extension = '.bmp'
            except:
                pass
            
            output_filename = f"{os.path.splitext(original_filename)[0]}_decrypted{extension}"
            output_path = os.path.join(output_dir, output_filename)
            
            # Write decrypted file
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            
            # Log completion
            self.console.log(f"Decryption complete!", "success")
            self.console.log(f"Decrypted file saved to: {output_filename}")
            
            # Update UI
            self.after(0, lambda: self.decryption_completed(output_path))
            
        except Exception as e:
            self.console.log(f"Decryption error: {str(e)}", "error")
            self.after(0, lambda: self.decryption_failed(str(e)))
    
    def decryption_completed(self, output_path):
        """Called when decryption is complete"""
        self.decrypting = False
        self.update_status("DECRYPTION COMPLETE")
        
        # Ask if user wants to open the decrypted file
        if messagebox.askyesno("Decryption Complete",
                              f"File decrypted successfully!\n\nDo you want to load the decrypted image?"):
            self.current_file = output_path
            self.current_file_type = "image"  
            self.file_info.configure(text=f"Image file:\n{os.path.basename(output_path)}")
            self.load_preview(output_path)
            self.update_status("READY TO ENCRYPT")
    
    def decryption_failed(self, error_message):
        """Called when decryption fails"""
        self.decrypting = False
        self.update_status("DECRYPTION FAILED")
        messagebox.showerror("Decryption Failed", 
                            f"Error during decryption:\n{error_message}\n\nPlease check your password.")
    
    def show_progress(self, message, duration=2.0, callback=None):
        """Show a progress dialog with animation"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Processing")
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        dialog.configure(fg_color=HackerTheme.SECONDARY)
        dialog.transient(self)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_y() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Message
        ctk.CTkLabel(
            dialog,
            text=message,
            font=("Courier New", 16, "bold"),
            text_color=HackerTheme.ACCENT
        ).pack(pady=(20, 10))
        
        # Progress bar
        progress_bar = HackerProgressBar(dialog, width=350)
        progress_bar.pack(pady=10, padx=20)
        
        # Status text with changing ellipsis
        status_label = ctk.CTkLabel(
            dialog,
            text="Working...",
            font=("Courier New", 12),
            text_color=HackerTheme.ACCENT
        )
        status_label.pack(pady=5)
        
        # Animate dots for status text
        def animate_dots():
            if not hasattr(animate_dots, "dots"):
                animate_dots.dots = 0
            animate_dots.dots = (animate_dots.dots + 1) % 4
            status_label.configure(text=f"Working{'.' * animate_dots.dots}")
            if dialog.winfo_exists():
                dialog.after(300, animate_dots)
        
        animate_dots()
        
        # Simulate progress and close when done
        def on_progress_complete():
            if dialog.winfo_exists():
                dialog.destroy()
            if callback:
                callback()
        
        progress_bar.simulate_progress(duration, on_progress_complete)


# ================ APPLICATION ENTRY POINT ================ #
if __name__ == "__main__":
    app = MadHatPixelEncryptor()
    app.mainloop()
        
        