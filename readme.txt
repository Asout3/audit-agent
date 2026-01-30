You're on Arch Linux. Python is locked to prevent system breakage. Use a virtual environment (the correct way):
bash
Copy
# 1. Create virtual environment in your project folder
python -m venv venv

# 2. Activate it (note the dot and space)
source venv/bin/activate

# 3. Now install packages (this will work)
pip install -r requirements.txt

# 4. Run your script
python main.py --build --focus Lending --count 300
To deactivate when done:
bash
Copy
deactivate
Every new terminal session, you must activate it first:
bash
Copy
cd deep-audit-agent
source venv/bin/activate
python main.py --audit /path/to/code
If you don't want to activate every time, use the full path:
bash
Copy
./venv/bin/python main.py --build --focus Lending --count 300