## to use this test for asana workspace 
1. you have to create a PAT in asana
2. run: ```export ASANA_ACCESS_TOKEN=``` in cli

# create a virtual environment for the test

3.  conda create -n test -y python=3.11 && conda activate test
4.  conda install pip
5.  pip install asana

# run the python test.py

6. conda run -n test python test.py