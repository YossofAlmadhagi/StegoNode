🛡️ Stegano Shield V27 — Final Gold
A robust and secure desktop application for concealing and encrypting confidential files inside carrier images using advanced steganography and cryptography.

🚀 Overview
Stegano Shield V27 (Final Gold) is a high-performance, cross-platform security tool designed to encode sensitive payloads into image containers seamlessly. It combines cryptographic password hashing with byte-level steganography to ensure complete non-repudiation, custom fingerprinting, and structural integrity protection.

🛠️ Requirements & Installation
System Requirements
Python 3.9 or higher installed on your system.

One-Time Setup
Clone or download this repository to your local machine.

Open your terminal/command prompt, navigate to the project directory, and install dependencies:

pip install -r requirements.txt

💻 Running the Application
To launch the graphical user interface (GUI), execute the main script:

python stegano_shield.py

📖 How to Use
🟩 1. "Encrypt / Decrypt" Tab
To Encrypt & Hide a File:
Select Carrier: Click on the designated image area or simply Drag & Drop an image file onto it.

Set Security: Input your encryption password (use the 👁️ icon to toggle visibility).

Execute: Click "Encrypt file inside image".

Choose Payload: Select the secret file you wish to conceal.

Save: Select the destination path for the newly generated output image.

To Decrypt & Extract a File:
Load Encrypted Carrier: Select the image containing the hidden payload.

Authorize: Enter the correct password.

Execute: Click "Decrypt and extract file".

Result: The hidden file will be automatically extracted and saved in its original format inside the Extracted_Files folder, created right next to your encrypted image.

🟨 2. "Version Upgrade" Tab
Designed to upgrade structural schemas of legacy encrypted assets (V23 / V25 / V26) to the modern V27 protocol without raw file re-extraction.

Enter the legacy password.

Input the new desired V27 password.

Click the upgrade button and choose the target directory containing your legacy assets.

Result: New V27-compliant secure images will be generated alongside the old files (Note: Legacy source files are preserved and not deleted automatically).

🔬 Automated Testing (Optional)
Validate the software core, cryptographic constraints, and edge cases locally:

python test_crypto.py

Test Case Coverage (16 Scenarios)
Pure V27 Encoding & Sequential Decoding loops
"Backward compatibility validation with legacy schemas (V23, V25, V26)"
Stress testing with heavy payloads (up to 2MB+)
"Non-ASCII character handling (e.g., Arabic file-naming structures)"
Zero-byte empty file bounds and edge-case exceptions
Carrier certification algorithms and fake fingerprint payload detection

✨ Release Changelog (What's Fixed in V27 Gold)
🔄 Schema Stability: Fixed structural encapsulation for V27 encoding/decoding loops.

📦 Backward Compatibility: Implemented comprehensive legacy structural processing engines for V23, V25, and V26.

🧼 Clean Truncation: Refactored upgrading engines to utilize fresh, clean source carriers during payload relocation.

📝 Metadata Integrity: Resolved payload filename mutations—original naming structures are strictly preserved post-upgrade.

🔍 Conflict Resolution: Integrated rfind byte-scoping mechanisms to prevent payload marker and signature collisions.

⚡ Interface Stability: Resolved UI freezing/crashing issues when shifting or dragging the desktop application window.

🛑 Error Mitigation: Implemented comprehensive pre-flight verification arrays before initiation of decryption sequences.

🎨 Contextual Feedback: Integrated dynamic, multi-color warning systems for user diagnostics based on exception severity.

⌨️ UX Overhaul: Added Drag & Drop capabilities, toggleable password visibility buttons, contextual operation logging automations, and automatic action locking to avoid process replication.

📜 Legal & Licensing
Author: YossofAlmadhagi

Copyright: Copyright © 2026 YossofAlmadhagi. All rights reserved.

License: This project is provided "As Is" without any express or implied warranties. Redistribution, modification, or unauthorized mirroring of this repository's source code without explicit attribution is strictly prohibited under intellectual property guidelines.

