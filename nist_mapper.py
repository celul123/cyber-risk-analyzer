def map_to_nist(vuln_name):

    vuln_name = vuln_name.lower()

    if "sql" in vuln_name:
        return "Protect"

    if "password" in vuln_name:
        return "Protect"

    if "malware" in vuln_name:
        return "Detect"

    if "phishing" in vuln_name:
        return "Respond"

    if "open port" in vuln_name:
        return "Identify"

    return "Detect"