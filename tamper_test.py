
from pathlib import Path

# Read the encrypted file
original = Path("sample.txt.enc")
data = bytearray(original.read_bytes())

# Modify one byte of the authentication tag
data[-1] ^= 1

# Save it as a separate tampered file
tampered = Path("sample_tampered.txt.enc")

with tampered.open("xb") as file:
    file.write(data)

print("Tampering simulation completed!")
print("Modified encrypted file:", tampered)
print("Original encrypted file remains unchanged.")
