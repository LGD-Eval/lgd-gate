import os
def run():
    target = os.environ.get("TARGET")
    os.system("ping " + target)
run()
