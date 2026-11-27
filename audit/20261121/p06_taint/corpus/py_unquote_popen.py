import os, urllib.parse
v = urllib.parse.unquote("%2F%65%74%63")
os.popen("cat " + v)
