import sys, subprocess
def go():
    host = sys.argv[1]
    subprocess.run("ssh " + host, shell=True)
go()
