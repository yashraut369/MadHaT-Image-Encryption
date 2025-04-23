#  MadHaT Image Encryptor v2.0 - by Yash (Popeye) 

A powerful, visually stunning image encryption/decryption GUI tool built in Python using `customtkinter`, with support for **AES (CBC/GCM)** and **ChaCha20** algorithms. Designed with MadHaT's signature neon-hacker theme.


GitHub Repo: [https://github.com/yashraut369/MadHaT-Image-Encryption](https://github.com/yashraut369/MadHaT-Image-Encryption)

---

## 🚀 Features

- 🔒 AES-256 CBC & GCM, ChaCha20, XChaCha20 encryption
- 🎨 Animated neon-themed GUI
- 🖼️ Live image preview & console output
- 💬 Typewriter text effects and real-time logs
- 🔐 Password strength meter
- 🔁 Fast image encryption/decryption to `.mhcrypt` format
- 📦 Simple `.mhcrypt` packaging with metadata

---


## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yashraut369/MadHaT-Image-Encryption.git
cd MadHaT-Image-Encryption
```

### 2. Create virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3. Install requirements

```bash
pip install -r requirements.txt
```


---

## 🧠 Usage

Run the main script:

```bash
python "MadHaT Image encryption.py"
```

Follow the GUI to select a file, choose your algorithm, enter a strong password, and hit **ENCRYPT** or **DECRYPT**.

---

## 🔐 Encryption Formats

Output file format: `.mhcrypt`  
Includes:
- Encrypted image bytes
- Algorithm metadata
- Salt, IV/Nonce, Tags (for GCM)
- File hash for integrity

---

## 👨‍💻 Author

Developed with 🔥 by **Yash (Popeye)** - creator of the MadHaT Community

---

## 📄 License

This project is licensed under the MIT License - feel free to fork, modify, and contribute!

---

