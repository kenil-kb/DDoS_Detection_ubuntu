import subprocess
import threading
import tkinter as tk
from tkinter import ttk

# Function to run the bash script and track output for dependency installation
def run_bash_script():
    global process
    try:
        # Run the bash script and capture stdout and stderr in real-time
        process = subprocess.Popen(
            ['bash', './run.sh'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Read stdout in real-time and track pip install progress
        for stdout_line in iter(process.stdout.readline, ""):
            if stdout_line:
                print(f"Output: {stdout_line.strip()}")
                if "START_PIP_INSTALL" in stdout_line:
                    print("Pip install started...")
                elif "END_PIP_INSTALL" in stdout_line:
                    print("Pip install completed. Closing loading window...")
                    close_loading_window()  # Close the window when pip install completes

        process.stdout.close()

        # Read stderr at the end
        stderr = process.stderr.read()
        if stderr:
            print(f"Error: {stderr.strip()}")

    except Exception as e:
        print(f"Exception occurred: {e}")
    finally:
        if process.poll() is None:  # Check if the process is still running
            process.wait()  # Wait for the Bash script to finish completely

# Function to show the loading window
def show_loading_window():
    global root
    root = tk.Tk()
    root.title("Please Wait")
    root.geometry("300x100")
    
    label = ttk.Label(root, text="Downloading dependencies. Please wait...", anchor="center")
    label.pack(pady=20)
    
    # Add a progress bar (just for visual purposes)
    progress = ttk.Progressbar(root, mode="indeterminate")
    progress.pack(pady=10)
    progress.start(10)  # Start the indeterminate progress bar
    
    # Prevent closing the window manually
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    # Start a separate thread to run the bash script
    threading.Thread(target=run_bash_script).start()
    
    root.mainloop()

# Function to close the loading window
def close_loading_window():
    if root:
        root.withdraw()

if __name__ == "__main__":
    show_loading_window()

