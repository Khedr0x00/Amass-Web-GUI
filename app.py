import os
import subprocess
import shlex
import json
from flask import Flask, render_template, request, jsonify, send_file
import threading
import queue
import time
import uuid # For unique filenames
import shutil # Added for shutil.which
import sys # To detect OS and get command-line arguments

app = Flask(__name__)

# Directory to store temporary files (e.g., uploaded wordlists, scan outputs)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# In-memory storage for scan outputs (for demonstration).
# In a real-world app, consider a more persistent and scalable solution (e.g., database, cloud storage).
scan_outputs = {}
scan_processes = {} # To keep track of running Amass processes
scan_queues = {} # To store queues for real-time output

# Load examples from amass_examples.txt
def load_examples(filename="amass_examples.txt"):
    """Loads examples from a JSON file."""
    try:
        # Assuming amass_examples.txt is in the same directory as app.py
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Examples file '{filename}' not found. Please ensure it's in the same directory as app.py.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from '{filename}': {e}")
        return []
    except Exception as e:
        print(f"An unexpected error occurred while loading examples: {e}")
        return []

ALL_EXAMPLES = load_examples()

@app.route('/')
def index():
    """Renders the main Amass GUI HTML page."""
    return render_template('index.html')

# New endpoint to serve Amass examples
@app.route('/get_examples', methods=['GET'])
def get_examples():
    """Returns the Amass examples as JSON."""
    return jsonify(ALL_EXAMPLES)

@app.route('/generate_command', methods=['POST'])
def generate_command():
    """Generates the Amass command based on form data."""
    data = request.json
    command_parts = ["amass"]

    def add_arg(arg_name, value):
        if value:
            command_parts.append(arg_name)
            command_parts.append(shlex.quote(str(value)))

    def add_checkbox_arg(arg_name, value):
        if value:
            command_parts.append(arg_name)

    # Main Domain
    if data.get('domain_entry'):
        command_parts.append("enum") # Amass enum is the primary subcommand
        command_parts.append("-d")
        command_parts.append(shlex.quote(data['domain_entry']))

    # Scan Types Tab
    if data.get('passive_scan_var'):
        add_checkbox_arg("-passive", True)
    if data.get('active_scan_var'):
        add_checkbox_arg("-active", True)
    if data.get('brute_force_var'):
        add_checkbox_arg("-brute", True)
    if data.get('wordlist_entry'):
        add_arg("-w", data.get('wordlist_entry'))
    if data.get('recursive_brute_var'):
        add_checkbox_arg("-r", True) # Amass uses -r for recursive brute-forcing
    if data.get('reverse_dns_var'):
        add_checkbox_arg("-noreverse", False) # -noreverse means NO reverse DNS, so if checked, don't add it.

    # Sources Tab
    if data.get('include_sources_entry'):
        add_arg("-src", data.get('include_sources_entry'))
    if data.get('exclude_sources_entry'):
        add_arg("-exclude", data.get('exclude_sources_entry'))
    if data.get('list_sources_var'):
        add_checkbox_arg("-show", True) # Amass uses -show to list data sources

    # Resolvers Tab
    if data.get('resolvers_entry'):
        add_arg("-r", data.get('resolvers_entry')) # Amass uses -r for resolvers
    if data.get('resolver_file_entry'):
        add_arg("-rf", data.get('resolver_file_entry'))

    # Output Tab
    if data.get('output_file_entry'):
        add_arg("-o", data.get('output_file_entry'))
    if data.get('json_output_file_entry'):
        add_arg("-json", data.get('json_output_file_entry'))
    if data.get('verbose_var'):
        add_checkbox_arg("-v", True)
    if data.get('silent_var'):
        add_checkbox_arg("-silent", True)
    if data.get('dir_output_entry'):
        add_arg("-dir", data.get('dir_output_entry'))

    # Exclusions/Inclusions Tab
    if data.get('blacklist_domains_entry'):
        add_arg("-bl", data.get('blacklist_domains_entry'))
    if data.get('whitelist_domains_entry'):
        add_arg("-wl", data.get('whitelist_domains_entry'))
    if data.get('blacklist_subdomains_entry'):
        add_arg("-blacklist", data.get('blacklist_subdomains_entry')) # Amass uses -blacklist for subdomains
    if data.get('whitelist_subdomains_entry'):
        add_arg("-whitelist", data.get('whitelist_subdomains_entry')) # Amass uses -whitelist for subdomains

    # Timing/Performance Tab
    if data.get('max_dns_queries_entry'):
        add_arg("-max-dns-queries", data.get('max_dns_queries_entry'))
    if data.get('max_retries_entry'):
        add_arg("-max-retries", data.get('max_retries_entry'))
    if data.get('timeout_entry'):
        add_arg("-timeout", data.get('timeout_entry'))
    if data.get('rate_limit_entry'):
        add_arg("-rate-limit", data.get('rate_limit_entry'))

    # Advanced Tab
    if data.get('config_file_entry'):
        add_arg("-config", data.get('config_file_entry'))
    if data.get('proxy_entry'):
        add_arg("-proxy", data.get('proxy_entry'))
    if data.get('http_headers_entry'):
        headers = data.get('http_headers_entry').strip()
        if headers:
            for header_line in headers.split('\n'):
                header_line = header_line.strip()
                if header_line:
                    command_parts.append("-headers")
                    command_parts.append(shlex.quote(header_line))
    if data.get('user_agent_entry'):
        add_arg("-user-agent", data.get('user_agent_entry'))
    if data.get('data_path_entry'):
        add_arg("-dir", data.get('data_path_entry')) # Amass uses -dir for data path
    if data.get('show_version_var'):
        add_checkbox_arg("-version", True)
    if data.get('show_help_var'):
        add_checkbox_arg("-h", True)

    additional_args = data.get('additional_args_entry', '').strip()
    if additional_args:
        try:
            split_args = shlex.split(additional_args)
            command_parts.extend(split_args)
        except ValueError:
            # Fallback if shlex can't parse, just add as a single string (less safe)
            command_parts.append(shlex.quote(additional_args))

    generated_cmd = " ".join(command_parts)
    return jsonify({'command': generated_cmd})

@app.route('/run_amass', methods=['POST'])
def run_amass():
    """
    Executes the Amass command received from the frontend.
    IMPORTANT: Running arbitrary commands from user input on a web server is a severe security risk.
    This implementation is for demonstration and should NOT be used in a production environment
    without extensive security measures, input validation, and sandboxing.
    """
    data = request.json
    command_str = data.get('command')
    scan_id = str(uuid.uuid4()) # Unique ID for this scan

    if not command_str:
        return jsonify({'status': 'error', 'message': 'No command provided.'}), 400

    # Basic check to prevent common dangerous commands. This is NOT exhaustive.
    if any(cmd in command_str for cmd in ['rm ', 'sudo ', 'reboot', 'shutdown', 'init ']):
        return jsonify({'status': 'error', 'message': 'Potentially dangerous command detected. Operation aborted.'}), 403

    # Use shlex.split to safely split the command string into a list
    try:
        command = shlex.split(command_str)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'Error parsing command: {e}'}), 400

    # Ensure amass is the command being run
    if command[0] != 'amass':
        return jsonify({'status': 'error', 'message': 'Only Amass commands are allowed.'}), 403

    # Check if amass executable exists using shutil.which
    if shutil.which(command[0]) is None:
        return jsonify({'status': 'error', 'message': f"Amass executable '{command[0]}' not found on the server. Please ensure Amass is installed and accessible in the system's PATH."}), 500

    # Create a new queue for this scan's real-time output
    output_queue = queue.Queue()
    scan_queues[scan_id] = output_queue
    scan_outputs[scan_id] = "" # Initialize full output storage

    def _run_amass_thread(cmd, q, scan_id_val):
        full_output_buffer = []
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Merge stderr into stdout for simpler real-time logging
                text=True,
                bufsize=1, # Line-buffered
                universal_newlines=True
            )
            scan_processes[scan_id_val] = process

            for line in iter(process.stdout.readline, ''):
                q.put(line) # Put each line into the queue
                full_output_buffer.append(line) # Also append to buffer for final output

            process.wait()
            return_code = process.returncode

            final_status_line = f"\nAmass finished with exit code: {return_code}\n"
            final_status_line += f"STATUS: {'Completed' if return_code == 0 else 'Failed'}\n"
            q.put(final_status_line) # Add final status to queue

            full_output_buffer.append(final_status_line)
            scan_outputs[scan_id_val] = "".join(full_output_buffer) # Store complete output

        except FileNotFoundError:
            error_msg = f"Error: '{cmd[0]}' command not found. Make sure Amass is installed and in your system's PATH.\nSTATUS: Error\n"
            q.put(error_msg)
            scan_outputs[scan_id_val] = error_msg
        except Exception as e:
            error_msg = f"An unexpected error occurred: {e}\nSTATUS: Error\n"
            q.put(error_msg)
            scan_outputs[scan_id_val] = error_msg
        finally:
            if scan_id_val in scan_processes:
                del scan_processes[scan_id_val]
            # Signal end of output by putting a special marker
            q.put("---SCAN_COMPLETE---")


    # Start the Amass process in a separate thread
    thread = threading.Thread(target=_run_amass_thread, args=(command, output_queue, scan_id))
    thread.daemon = True
    thread.start()

    return jsonify({'status': 'running', 'scan_id': scan_id, 'message': 'Amass scan started.'})

# Modified get_scan_output to handle 'amass_install' ID
@app.route('/get_scan_output/<scan_id>', methods=['GET'])
def get_scan_output(scan_id):
    """
    Polls for real-time Amass scan output.
    Returns new lines from the queue or the final output if scan is complete.
    """
    output_queue = scan_queues.get(scan_id)
    if not output_queue:
        # If queue is not found, check if the scan completed and its final output is stored
        final_output = scan_outputs.get(scan_id)
        final_status = scan_outputs.get(scan_id + "_status") # Check for installation status
        if final_output and final_status:
            return jsonify({'status': final_status, 'output': final_output})
        elif final_output: # If it's a regular scan that completed
            return jsonify({'status': 'completed', 'output': final_output})
        return jsonify({'status': 'not_found', 'message': 'Scan ID not found or expired.'}), 404

    new_output_lines = []
    scan_finished = False
    install_success = False
    install_failure = False

    try:
        while True:
            # Get items from queue without blocking
            line = output_queue.get_nowait()
            if line == "---SCAN_COMPLETE---":
                scan_finished = True
                break
            elif line == "---INSTALL_COMPLETE_SUCCESS---":
                install_success = True
                scan_finished = True # Treat installation completion as a scan completion for frontend
                break
            elif line == "---INSTALL_COMPLETE_FAILURE---":
                install_failure = True
                scan_finished = True # Treat installation completion as a scan completion for frontend
                break
            new_output_lines.append(line)
    except queue.Empty:
        pass # No more lines in queue for now

    current_output_segment = "".join(new_output_lines)

    if scan_finished:
        # Scan or installation is truly complete, clean up the queue
        del scan_queues[scan_id]
        status_to_return = 'completed'
        if install_success:
            status_to_return = 'success'
        elif install_failure:
            status_to_return = 'error'
        
        # Ensure the final output includes all accumulated output
        final_output_content = scan_outputs.get(scan_id, "Scan/Installation completed, but output not fully captured.")
        return jsonify({'status': status_to_return, 'output': final_output_content})
    else:
        # Scan/Installation is still running, return partial output
        return jsonify({'status': 'running', 'output': current_output_segment})


@app.route('/save_output', methods=['POST'])
def save_output():
    """Saves the provided content to a file on the server and allows download."""
    data = request.json
    content = data.get('content')
    filename = data.get('filename', f'amass_output_{uuid.uuid4()}.txt')

    if not content:
        return jsonify({'status': 'error', 'message': 'No content to save.'}), 400

    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        return jsonify({'status': 'success', 'message': 'File saved successfully.', 'download_url': f'/download_output/{filename}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to save file: {e}'}), 500

@app.route('/download_output/<filename>')
def download_output(filename):
    """Allows downloading a previously saved output file."""
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'status': 'error', 'message': 'File not found.'}), 404

@app.route('/install_amass', methods=['POST'])
def install_amass():
    """
    Attempts to install Amass on the server (Linux/Termux only).
    WARNING: This endpoint executes system commands with 'sudo'.
    This is a significant security risk and should ONLY be used in a
    controlled, isolated development environment where you fully trust
    the users and the environment. In a production setting, exposing
    such functionality is highly discouraged.
    """
    data = request.json
    platform_type = data.get('platform') # 'linux' or 'termux'

    # Check if running on Linux or Termux (sys.platform for Termux is 'linux')
    if sys.platform.startswith('linux'):
        scan_id = str(uuid.uuid4()) # Unique ID for this installation process
        output_queue = queue.Queue()
        scan_queues[scan_id] = output_queue
        scan_outputs[scan_id] = "" # Initialize full output storage for this ID

        def _install_thread(q, current_scan_id, p_type):
            temp_buffer_thread = [] # Local buffer for the thread
            try:
                if p_type == 'termux':
                    # Amass might not be directly in pkg, often installed via go get or precompiled binary
                    # For simplicity, let's assume 'go' is available and try 'go install' or direct download
                    # A more robust solution would be to check for precompiled binaries or guide the user.
                    # For now, let's suggest a common way or provide a placeholder for direct binary install.
                    # As a fallback, we'll try to install `go` and then `amass`.
                    q.put("Detected Termux. Attempting to install Go and then Amass.\n")
                    commands = [
                        shlex.split("pkg update -y"),
                        shlex.split("pkg install go -y"),
                        shlex.split("go install -v github.com/owasp-amass/amass/v4@latest")
                    ]
                elif p_type == 'linux':
                    # For Linux, often installed via apt/snap or go get
                    q.put("Detected Linux. Attempting to install Go and then Amass.\n")
                    commands = [
                        shlex.split("sudo apt update -y"),
                        shlex.split("sudo apt install -y golang"), # Install Go
                        shlex.split("go install -v github.com/owasp-amass/amass/v4@latest") # Install Amass
                    ]
                else:
                    q.put("Error: Unsupported platform type for installation.\n")
                    q.put("---INSTALL_COMPLETE_FAILURE---")
                    return

                for cmd in commands:
                    q.put(f"Executing: {' '.join(cmd)}\n")
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        universal_newlines=True
                    )
                    for line in iter(process.stdout.readline, ''):
                        q.put(line)
                        temp_buffer_thread.append(line)
                    process.wait()
                    if process.returncode != 0:
                        q.put(f"Command failed with exit code {process.returncode}: {' '.join(cmd)}\n")
                        raise subprocess.CalledProcessError(process.returncode, cmd, "".join(temp_buffer_thread), "")
                
                # Signal success and store final output
                q.put("---INSTALL_COMPLETE_SUCCESS---")
                scan_outputs[current_scan_id] = "".join(temp_buffer_thread)

            except subprocess.CalledProcessError as e:
                error_output = f"Command failed with exit code {e.returncode}:\n{e.stdout}"
                q.put(error_output)
                q.put("---INSTALL_COMPLETE_FAILURE---")
                scan_outputs[current_scan_id] = "".join(temp_buffer_thread) + error_output
            except FileNotFoundError as e:
                error_msg = f"Error: Command not found ({e}). Ensure 'sudo'/'apt'/'pkg'/'go' is installed and in PATH.\n"
                q.put(error_msg)
                q.put("---INSTALL_COMPLETE_FAILURE---")
                scan_outputs[current_scan_id] = "".join(temp_buffer_thread) + error_msg
            except Exception as e:
                error_msg = f"An unexpected error occurred during installation: {str(e)}\n"
                q.put(error_msg)
                q.put("---INSTALL_COMPLETE_FAILURE---")
                scan_outputs[current_scan_id] = "".join(temp_buffer_thread) + error_msg

        # Start the installation in a separate thread
        install_thread = threading.Thread(target=_install_thread, args=(output_queue, scan_id, platform_type))
        install_thread.daemon = True
        install_thread.start()

        return jsonify({
            'status': 'running',
            'scan_id': scan_id, # Return the unique ID for polling
            'message': f'Amass installation for {platform_type} started. Polling for output...'
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'Amass installation via this interface is only supported on Linux/Termux systems. For Windows, please use the download link.',
            'output': 'Operating system is not Linux or Termux.'
        }), 400

# Function to gracefully shut down the Flask server
def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/shutdown', methods=['POST'])
def shutdown():
    """Endpoint to gracefully shut down the Flask application."""
    print("Received shutdown request.")
    # You might want to add authentication/authorization here in a real app
    shutdown_server()
    return 'Server shutting down...', 200

if __name__ == '__main__':
    # Default port if no argument is provided (e.g., if run directly)
    port = 5000 # This will be overridden by the PHP dashboard

    # Check for a --port argument passed from the PHP dashboard
    if '--port' in sys.argv:
        try:
            # Get the index of '--port' and then the next argument (which is the port number)
            port_index = sys.argv.index('--port') + 1
            port = int(sys.argv[port_index])
        except (ValueError, IndexError):
            print("Warning: Invalid or missing port argument for sub-app. Using default port.")
    
    print(f"Amass sub-app is starting on port {port}...") # Added for clarity in logs
    app.run(debug=True, host='0.0.0.0', port=port)

