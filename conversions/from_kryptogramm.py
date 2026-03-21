import argparse
import json


def convert(path: str):
    with open(path) as f:
        old = json.load(f)

    if "ephemeral" in old:
        print(f"Skipping {path}")
        return

    new = {
        "ephemeral": old["Ephemeral"],
        "voteId": old["VoteID"],
        "result": old["result"],
    }

    with open(path, "w") as f:
        json.dump(new, f, indent=2)

    print(f"Converted: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert JSON from 'kryptogramm' to 'voteverif'")
    parser.add_argument("files", nargs="+", help="JSON files to migrate")
    args = parser.parse_args()

    for path in args.files:
        convert(path)
