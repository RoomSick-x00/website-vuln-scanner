


def format_submit_response(data):
    print("Scan submitted successfully ✅")
    print(f"Scan ID: {data['scan_id']}")


def format_status_response(data):
    print(f"Scan ID : {data['scan_id']}")
    print(f"Status  : {data['status'].upper()} ⏳")
