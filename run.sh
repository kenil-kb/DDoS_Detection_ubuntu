#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Step 1: Activate the virtual environment
echo "Creating the virtual environment (Could take up to 10 minutes for the first time)..."

# Check if the virtual environment already exists
if [ -d "venv" ]; then
    echo "Virtual environment already exists. Activating..."
    source "venv/bin/activate"
    
    echo "START_PIP_INSTALL"  # Add a marker to signal pip install starting

    pip install -r req.txt

    echo "END_PIP_INSTALL"  # Add a marker to signal pip install completion
else
    echo "Creating virtual environment..."
    python3 -m venv "venv"
    source "venv/bin/activate"
    
    echo "START_PIP_INSTALL"  # Add a marker to signal pip install starting

    pip install -r req.txt

    echo "END_PIP_INSTALL"  # Add a marker to signal pip install completion
fi

# Step 2: Run the Python script (this part should run after the popup closes)
echo "Running Python script..."
python3 test_ddos.py

