import argparse
import json


def convert(path: str):
    with open(path) as f:
        old = json.load(f)

    if "result" in old:
        print(f"Skipping {path}")
        return

    new = {
        "ephemeral": old["rand"],
        "voteId": old["voteId"],
        "result": {
            "Qualification": {
                "ocsp": old["ocsp"],
                "tspreg": old["tspreg"],
            },
            "SessionID": old["sessionId"],
            "Type": "bdoc",
            "Vote": old["vote"],
            "ChoicesList": old["choices_list"],
        },
    }

    with open(path, "w") as f:
        json.dump(new, f, indent=2)

    print(f"Converted: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert legacy saved vote JSON files to the current version")
    parser.add_argument("files", nargs="+", help="JSON files to migrate")
    args = parser.parse_args()

    for path in args.files:
        convert(path)
