import json
from datetime import datetime


def save_results(data):

    filename = "results.json"

    report = {
        "timestamp": str(datetime.now()),
        "scan_results": data
    }

    with open(filename, "w") as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print(f"\n[+] Results saved to {filename}")