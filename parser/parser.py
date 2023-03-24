import xml.etree.ElementTree as ET

import html
import click
import jinja2

NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.1"}

def slugify(text):
    return text.replace("-", "_")

def render_task_file(context, template, filename=None):
    context["stig_id_slug"] = slugify(context['stig_id'].replace("-", "_"))
    if filename is None:
        filename = context["stig_id_slug"] + ".yml"
    rendered = template.render(**context)
    with open(filename, "w") as ouptut_fh:
        ouptut_fh.write(rendered)

def nist_from_cci(cci: str):
    pass

def find_and_parse(root: ET.Element, xpath: str, ns=NS):
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
@click.argument('input_file', type=click.Path())
@click.option('--template-file', type=click.Path(), default="./task_template.yml.j2")
def cli(input_file, template_file):
    with open(input_file) as input_fh:
        tree=ET.fromstring(input_fh.read())

    with open(template_file) as template_fh:
        template = jinja2.Template(template_fh.read())

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
        render_task_file(context=control, template=template)


if __name__ == "__main__":
    cli()