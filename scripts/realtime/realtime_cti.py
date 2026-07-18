import requests
from datetime import datetime, timedelta, UTC


def get_latest_cves(limit=5):

    # ✅ FIXED (no deprecation warning)
    end_date = datetime.now(UTC)
    start_date = end_date - timedelta(days=3)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 20
    }

    try:
        print("🔍 Fetching CVEs from NVD...")

        response = requests.get(url, params=params, timeout=15)

        print("Status Code:", response.status_code)

        if response.status_code != 200:
            print("❌ API failed, using fallback...")
            return fallback_cves(limit)

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        print("Fetched CVEs:", len(vulnerabilities))

        # If empty → fallback
        if not vulnerabilities:
            print("⚠️ No recent CVEs found, using fallback...")
            return fallback_cves(limit)

        # Sort latest first
        vulnerabilities = sorted(
            vulnerabilities,
            key=lambda x: x["cve"].get("published", ""),
            reverse=True
        )

        results = []

        for item in vulnerabilities[:limit]:
            cve = item["cve"]

            cve_id = cve.get("id", "N/A")

            desc = cve.get("descriptions", [])
            description = desc[0]["value"] if desc else "No description"

            severity = "N/A"
            try:
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV30" in metrics:
                    severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
            except Exception as e:
                print("Severity error:", e)

            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "description": description[:120]
            })

        return results

    except Exception as e:
        print("❌ MAIN ERROR:", e)
        return fallback_cves(limit)


# -----------------------------
# FALLBACK FUNCTION
# -----------------------------
def fallback_cves(limit=5):

    print("🔁 Running fallback...")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"

    try:
        response = requests.get(url, timeout=10)
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        print("Fallback CVEs:", len(vulnerabilities))

        vulnerabilities = sorted(
            vulnerabilities,
            key=lambda x: x["cve"].get("published", ""),
            reverse=True
        )

        results = []

        for item in vulnerabilities[:limit]:
            cve = item["cve"]

            cve_id = cve.get("id", "N/A")

            desc = cve.get("descriptions", [])
            description = desc[0]["value"] if desc else "No description"

            results.append({
                "cve_id": cve_id,
                "severity": "N/A",
                "description": description[:120]
            })

        return results

    except Exception as e:
        print("❌ FALLBACK ERROR:", e)
        return []


# -----------------------------
# TEST BLOCK
# -----------------------------
if __name__ == "__main__":

    cves = get_latest_cves()

    print("\n🔥 Latest CVEs:\n")

    if not cves:
        print("❌ No CVEs retrieved!")
    else:
        for c in cves:
            print(f"{c['cve_id']} | {c['severity']}")
            print(c["description"])
            print("-" * 60)