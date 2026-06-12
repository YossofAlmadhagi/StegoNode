<h1>🛡️ Stegano Shield V27 — Final Gold</h1>
<p><strong>A robust and secure desktop application for concealing and encrypting confidential files inside carrier images using advanced steganography and cryptography.</strong></p>

<hr>

<h2>🚀 Overview</h2>
<p>Stegano Shield V27 (Final Gold) is a high-performance, cross-platform security tool designed to encode sensitive payloads into image containers seamlessly. It combines cryptographic password hashing with byte-level steganography to ensure complete non-repudiation, custom fingerprinting, and structural integrity protection.</p>

<hr>

<h2>🛠️ Requirements & Installation</h2>
<h3>System Requirements</h3>
<ul>
  <li>Python 3.9 or higher installed on your system.</li>
</ul>

<h3>One-Time Setup</h3>
<p>1. Clone or download this repository to your local machine.<br>
2. Open your terminal/command prompt, navigate to the project directory, and install dependencies:</p>
<pre><code>pip install -r requirements.txt</code></pre>

<hr>

<h2>💻 Running the Application</h2>
<p>To launch the graphical user interface (GUI), execute the main script:</p>
<pre><code>python stegano_shield.py</code></pre>

<hr>

<h2>🔥Quick Installation</h2>
<p>Run the StegoNode_Setup.exe and follow the quick and easy installation instructions.</p>
<pre><code>StegoNode_Setup.exe</code></pre>

<h2>📖 How to Use</h2>

<h3>🟩 1. "Encrypt / Decrypt" Tab</h3>

<h4>To Encrypt & Hide a File:</h4>
<ol>
  <li><strong>Select Carrier:</strong> Click on the designated image area or simply Drag & Drop an image file onto it.</li>
  <li><strong>Set Security:</strong> Input your encryption password.</li>
  <li><strong>Execute:</strong> Click "Encrypt file inside image".</li>
  <li><strong>Choose Payload:</strong> Select the secret file you wish to conceal.</li>
  <li><strong>Save:</strong> Select the destination path for the newly generated output image.</li>
</ol>

<h4>To Decrypt & Extract a File:</h4>
<ol>
  <li><strong>Load Encrypted Carrier:</strong> Select the image containing the hidden payload.</li>
  <li><strong>Authorize:</strong> Enter the correct password.</li>
  <li><strong>Execute:</strong> Click "Decrypt and extract file".</li>
  <li><strong>Result:</strong> The hidden file will be automatically extracted and saved in its original format inside the "Extracted_Files" folder.</li>
</ol>

<hr>

<h3>🟨 2. "Version Upgrade" Tab</h3>
<p>Designed to upgrade structural schemas of legacy encrypted assets (V23 / V25 / V26) to the modern V27 protocol without raw file re-extraction.</p>
<ol>
  <li>Enter the legacy password.</li>
  <li>Input the new desired V27 password.</li>
  <li>Click the upgrade button and choose the target directory containing your legacy assets.</li>
  <li><strong>Result:</strong> New V27-compliant secure images will be generated alongside the old files (Legacy source files are preserved).</li>
</ol>

<hr>

<h2>🔬 Automated Testing (Optional)</h2>
<p>Validate the software core, cryptographic constraints, and edge cases locally:</p>
<pre><code>python test_crypto.py</code></pre>

<table border="1" cellpadding="8" cellspacing="0">
  <thead>
    <tr style="background-color: #222; color: white;">
      <th>Test Case Coverage (16 Scenarios)</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>• Pure V27 Encoding & Sequential Decoding loops</td></tr>
    <tr><td>• Backward compatibility validation with legacy schemas (V23, V25, V26)</td></tr>
    <tr><td>• Stress testing with heavy payloads (up to 2MB+)</td></tr>
    <tr><td>• Non-ASCII character handling (e.g., Arabic file-naming structures)</td></tr>
    <tr><td>• Zero-byte empty file bounds and edge-case exceptions</td></tr>
    <tr><td>• Carrier certification algorithms and fake fingerprint payload detection</td></tr>
  </tbody>
</table>

<hr>

<h2>✨ Release Changelog (What's Fixed in V27 Gold)</h2>
<ul>
  <li><strong>Schema Stability:</strong> Fixed structural encapsulation for V27 encoding/decoding loops.</li>
  <li><strong>Backward Compatibility:</strong> Implemented comprehensive legacy structural processing engines for V23, V25, and V26.</li>
  <li><strong>Clean Truncation:</strong> Refactored upgrading engines to utilize fresh, clean source carriers during payload relocation.</li>
  <li><strong>Metadata Integrity:</strong> Resolved payload filename mutations—original naming structures are strictly preserved post-upgrade.</li>
  <li><strong>Conflict Resolution:</strong> Integrated rfind byte-scoping mechanisms to prevent payload marker and signature collisions.</li>
  <li><strong>Interface Stability:</strong> Resolved UI freezing/crashing issues when shifting or dragging the desktop application window.</li>
  <li><strong>UX Overhaul:</strong> Added Drag & Drop capabilities, toggleable password visibility buttons, contextual operation logging automations, and automatic action locking to avoid process replication.</li>
</ul>

<hr>

<h2>📜 Legal & Licensing</h2>
<ul>
  <li><strong>Author:</strong> YossofAlmadhagi</li>
  <li><strong>Copyright:</strong> Copyright © 2026 YossofAlmadhagi. All rights reserved.</li>
  <li><strong>License:</strong> This project is provided "As Is" without any express or implied warranties. Redistribution, modification, or unauthorized mirroring of this repository's source code without explicit attribution is strictly prohibited under intellectual property guidelines.</li>
</ul>