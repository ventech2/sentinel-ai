import base64
import os
import subprocess

decoded_command = base64.b64decode("ZWNobyBoZWxsbw==").decode()
subprocess.run(decoded_command, shell=True)

external_command = "echo " + request.args.get("command")
os.system(external_command)
