from ioc_typing import IOCClassifier

# Our type vocabulary (SPEC §6): file | ip | domain | url
FILE = "file"
IP = "ip"
DOMAIN = "domain"
URL = "url"

# D10: VT addresses files by exactly these hash algorithms.
_SUPPORTED_HASHES = {"md5", "sha1", "sha256"}

_classifier = IOCClassifier()


def resolve_type(artifact: str) -> str | None:
    """Classify an artifact into our type vocabulary; None means 'not a supported IOC'.

    ioc-typing reports hashes as type_pri='hash'; we translate to 'file' (the
    VT object a hash addresses) and enforce the D10 algorithm restriction.
    The classifier never raises — garbage comes back as determined=False.
    """
    result = _classifier.classify(artifact)
    if not result["determined"]:
        return None
    match result["type_pri"]:
        case "hash":
            return FILE if result["type_sec"] in _SUPPORTED_HASHES else None
        case "ip":
            return IP
        case "domain":
            return DOMAIN
        case "url":
            return URL
        case _:
            # Determined but outside our vocabulary: unsupported (SPEC §7).
            return None
