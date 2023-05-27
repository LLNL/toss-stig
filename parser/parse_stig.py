#! /usr/bin/env python3

import os
import html
import xml.etree.ElementTree as ET

import click
import jinja2

NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.1"}


def slugify(text):
    return text.replace("-", "_")


def render_task_file(context, template, output_dir=".", filename=None):
    context["stig_id_slug"] = slugify(context["stig_id"].replace("-", "_"))
    if filename is None:
        filename = context["stig_id_slug"] + ".yml"
    output_path = os.path.join(os.path.abspath(output_dir), filename)
    rendered = template.render(**context)
    rendered = "\n".join(line.rstrip() for line in rendered.splitlines())
    with open(output_path, "w") as output_fh:
        output_fh.write(rendered)


def nist_from_cci(cci: str):
    pass


def find_and_parse(root: ET.Element, xpath: str, ns=NS):
    element = root.find(xpath, ns)
    if element is None:
        return ""
    text = element.text
    text = html.unescape(text)
    if xpath == "./xccdf:Rule/xccdf:description":
        description = ET.fromstring("<xml>" + text + "</xml>")
        text = find_and_parse(description, "./VulnDiscussion")
    elif xpath == "./xccdf:Rule/xccdf:title":
        text = " ".join(line.strip() for line in text.splitlines())
    if xpath in [
        "./xccdf:Rule/xccdf:fixtext",
        "./xccdf:Rule/xccdf:description",
        "./xccdf:Rule/xccdf:check/xccdf:check-content",
    ]:
        text = "\n".join(line.strip() for line in text.splitlines())
    return text


@click.command()
@click.argument("input_file", type=click.Path())
@click.option(
    "--template-file", type=click.Path(exists=True), default="./task_template.yml.j2"
)
@click.option("--output-dir", type=click.Path(exists=True), default="./output")
def cli(input_file, template_file, output_dir):
    with open(input_file) as input_fh:
        tree = ET.fromstring(input_fh.read())

    with open(template_file) as template_fh:
        template = jinja2.Template(template_fh.read())

    if not os.path.isdir(output_dir):
        raise NotADirectoryError(
            "The output directory " + output_dir + " must be a directory."
        )

    for group in tree.findall("xccdf:Group", NS):
        control = {
            "vuln_id": group.attrib["id"],
            "severity": group.find("./xccdf:Rule", NS).attrib["severity"],
            "group_title": find_and_parse(group, "xccdf:title"),
            "rule_id": group.find("./xccdf:Rule", NS).attrib["id"],
            "stig_id": find_and_parse(group, "./xccdf:Rule/xccdf:version"),
            "rule_title": find_and_parse(group, "./xccdf:Rule/xccdf:title"),
            "discussion": find_and_parse(group, "./xccdf:Rule/xccdf:description"),
            "check_text": find_and_parse(
                group, "./xccdf:Rule/xccdf:check/xccdf:check-content"
            ),
            "fix_text": find_and_parse(group, "./xccdf:Rule/xccdf:fixtext"),
            "cci": [
                ident.text
                for ident in group.findall(
                    "./xccdf:Rule/xccdf:ident[@system='http://cyber.mil/cci']", NS
                )
            ],
        }
        render_task_file(context=control, template=template, output_dir=output_dir)


if __name__ == "__main__":
    cli()
