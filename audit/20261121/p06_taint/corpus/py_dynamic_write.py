import sys
def save():
    p = sys.argv[1]
    f = open(p, "w")
    f.write("x")
save()
