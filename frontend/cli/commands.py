import requests

BASE_URL = "http://backend:8000"


def submit_scan(url):

    payload = {
        "target": url,
        "scan_type": "full"
    }

    try:
        response = requests.post(
            f"{BASE_URL}/scans/",
            json=payload
        )

        print("STATUS:", response.status_code)
        print("RESPONSE:", response.text)

        if response.status_code != 200:
            return {
                "error": f"Backend error: {response.text}"
            }

        return response.json()

    except Exception as e:
        return {
            "error": str(e)
        }


def get_results(scan_id):

    try:
        response = requests.get(
            f"{BASE_URL}/scans/{scan_id}"
        )

        print("STATUS:", response.status_code)
        print("RESPONSE:", response.text)

        if response.status_code != 200:
            return {
                "error": f"Backend error: {response.text}"
            }

        return response.json()

    except Exception as e:
        return {
            "error": str(e)
        }