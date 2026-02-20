import argparse
import commands
import formatter

def handle_submit(args):
    response = commands.submit_scan(args.url)
    formatter.format_submit_response(response)



def handle_status(args):
    response = commands.check_status(args.id)
    formatter.format_status_response(response)


def handle_results(args):
    response = commands.get_results(args.id)
    formatter.format_results_response(response)



def main():
    # Create the top-level parser
    parser = argparse.ArgumentParser(
        description="Website Vulnerability Scanner CLI"
    )

    # Subparsers = different commands
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ----- submit command -----
    submit_parser = subparsers.add_parser(
        "submit", help="Submit a new scan"
    )
    submit_parser.add_argument(
        "--url", required=True, help="Target URL to scan"
    )
    submit_parser.set_defaults(func=handle_submit)

    # ----- status command -----
    status_parser = subparsers.add_parser(
        "status", help="Check scan status"
    )
    status_parser.add_argument(
        "--id", required=True, help="Scan ID"
    )
    status_parser.set_defaults(func=handle_status)

    # ----- results command -----
    results_parser = subparsers.add_parser(
        "results", help="Get scan results"
    )
    results_parser.add_argument(
        "--id", required=True, help="Scan ID"
    )
    results_parser.set_defaults(func=handle_results)

    # Parse arguments
    args = parser.parse_args()

    # Call the correct handler function
    args.func(args)


if __name__ == "__main__":
    main()
