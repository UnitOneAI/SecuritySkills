from defusedxml.ElementTree import fromstring


def parse_metadata(xml_body: bytes):
    return fromstring(xml_body)
