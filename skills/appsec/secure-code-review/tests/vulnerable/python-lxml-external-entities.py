from lxml import etree


def parse_support_bundle(xml_body: bytes):
    parser = etree.XMLParser(
        resolve_entities=True,
        load_dtd=True,
        no_network=False,
        huge_tree=True,
    )
    return etree.fromstring(xml_body, parser=parser)
