def parse_cvss(vector):

    score = 0

    if "AV:N" in vector:
        score += 3

    if "AC:L" in vector:
        score += 2

    if "PR:N" in vector:
        score += 2

    if "C:H" in vector:
        score += 1

    if "I:H" in vector:
        score += 1

    if "A:H" in vector:
        score += 1

    return score