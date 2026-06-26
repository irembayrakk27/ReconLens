import json


def save_report(data, filename="report.json"):

    with open(filename, "w") as file:

        json.dump(
            data,
            file,
            indent=4
        )

    print(f"Report saved to {filename}")