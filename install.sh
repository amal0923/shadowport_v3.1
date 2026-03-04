#!/bin/bash
# ShadowPort v3.1 Installer Script

echo "🔧 Installing ShadowPort dependencies..."

# Update package lists
sudo apt update

# Ensure Python 3 is installed
sudo apt install -y python3 python3-pip

# Make main script executable
chmod +x shadowport_v3.py

echo "✅ Installation complete. You can now run:"
echo "   python3 shadowport_v3.py <target> -rL"

