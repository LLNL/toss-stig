import xml.etree.ElementTree as ET

import html
import click
import jinja2

NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.1"}

def find_and_parse(root, xpath, ns=NS):
    element=root.find(xpath, ns)
    if element is None:
        return ""
    text = element.text
    text = html.unescape(text)

    if xpath == "./xccdf:Rule/xccdf:description":
        description = ET.fromstring("<xml>" + text + "</xml>")
        text = find_and_parse(description, "./VulnDiscussion")    
    elif xpath == "./xccdf:Rule/xccdf:title":
        text = " ".join(line.strip() for line in text.splitlines())
    
    if xpath in ["./xccdf:Rule/xccdf:fixtext", "./xccdf:Rule/xccdf:description", "./xccdf:Rule/xccdf:check/xccdf:check-content"]:
        text = "\n".join(line.strip() for line in text.splitlines())
    return text

@click.command()
@click.argument('input_file', type=click.File('rb'))
def cli(input_file):
    tree=ET.fromstring(input_file.read())
    for group in tree.findall("xccdf:Group", NS):
        control = {
            "vuln_id": group.attrib["id"],
            "severity": group.find("./xccdf:Rule", NS).attrib["severity"],
            "group_title": find_and_parse(group, "xccdf:title"),
            "rule_id": group.find("./xccdf:Rule", NS).attrib["id"],
            "stig_id": find_and_parse(group, "./xccdf:Rule/xccdf:version"),
            "rule_title": find_and_parse(group, "./xccdf:Rule/xccdf:title"),
            "discussion": find_and_parse(group, "./xccdf:Rule/xccdf:description"),
            "check_text": find_and_parse(group, "./xccdf:Rule/xccdf:check/xccdf:check-content"),
            "fix_text": find_and_parse(group, "./xccdf:Rule/xccdf:fixtext"),
            "cci": [ident.text for ident in group.findall("./xccdf:Rule/xccdf:ident[@system='http://cyber.mil/cci']", NS)],
        }
        print(control)


if __name__ == "__main__":
    cli()