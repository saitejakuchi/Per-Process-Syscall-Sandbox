# Per-Process-Syscall-Sandbox

- Contains code for Assignents that is done as part of crediting the course (E0-256 Computer System Security).

## Process to generate the graph and run the detection algorithm:-

  {virtual_env} -> Name of the virtual environment.
  {exe_file_path} -> Path to the executable file in the local running machine.
  {path_to_requirements} -> Path to requirements.txt in the local running machine.
  {path_to_notebook} -> Path to the Part1.ipynb in the local running machine.

  1) Install Jupyter notebook using "pip install jupyter" respectively. <br><br>
  2) Create a virtual env using "python -m venv {virtual_env}", activate the virtual env using a command that is specific to the machine that is being runned on and install required packages (Required packages for this project are in requirements.txt attached.) using "pip install -r {path_to_requirements}" <br><br>
  3) Now run the following command so that jupyter notebook can use the created virtual env as kernel 
    "ipython kernel install --user --name={virtual_env}" <br><br>

  4) Run the following command to get the dot file which has the required data.
    a) For linux users :-  
    "EXE_FILE={exe_file_path} jupyter nbconvert --to html {path_to_notebook} --stdout --ExecutePreprocessor.kernel_name={virtual_env} --ExecutePreprocessor.enabled=True" 
    b) For windows :- 
      "set EXE_FILE={exe_file_path} jupyter nbconvert --to html {path_to_notebook} --stdout --ExecutePreprocessor.kernel_name={virtual_env} --ExecutePreprocessor.enabled=True" 

  5) A pickle file (graph data of binary) with same name that of the binary will be generated in the same directory as that of the above .ipynb file which is then later used for further process.

  6) To run the detection algorithm use "python detect.py {exe_name}". In either of the case where the binary or the pickle file (graph data of binary) is missing the program will show the respective warning.
    Incase both the files are available then it detects possible attack scenario of the binary with respective of the graph data.
