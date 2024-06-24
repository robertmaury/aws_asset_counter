To set up a Python virtual environment (venv) on macOS, you'll first need to ensure you have Python installed. You can verify this by opening the Terminal and typing python3 --version. If Python is not installed, you can install it from the official Python website or via Homebrew using brew install python3.

Once Python is installed, you can create a virtual environment by following these steps:

    1. Open Terminal.
    2. Navigate to the directory where you want to create your virtual environment.
    3. Run the command "python3 -m venv myenv" to create a virtual environment named "myenv".
    4. Activate the virtual environment by running "source myenv/bin/activate". You'll notice the command prompt changes to indicate that you are now working inside myenv.
    5. Once activated, you can install Python packages within this environment using pip install package-name.

To deactivate the virtual environment and return to your global Python environment, use the command deactivate.

To install dependencies in your venv run:

"python3 -m pip install boto3 pandas botocore.errorfactory"