from ruamel import yaml
import os
from io import StringIO
from typing import Optional, AnyStr, Dict
from cvebased.common import dedupe_sort


def compile_researcher(path_to_repo, data):
    filepath = os.path.join(path_to_repo, 'researcher', f"{data['alias']}.md")

    # move bio from yaml field to markdown content
    markdown = ''
    if 'bio' in data:
        markdown = data['bio']
        data = {key: val for key, val in data.items() if key != 'bio'}

    write_md(filepath, data, markdown)
    return filepath


def compile_cve(path_to_repo, data):
    dirpath = cve_sequence_dir(os.path.join(path_to_repo, 'cve'), data['id'])
    if not os.path.exists(dirpath):
        os.makedirs(dirpath)
    filepath = os.path.join(dirpath, f"{data['id']}.md")

    # move advisory from yaml field to markdown content
    markdown = ''
    if 'advisory' in data:
        markdown = data['advisory']
        data = {key: val for key, val in data.items() if key != 'advisory'}

    write_md(filepath, data, markdown)
    return filepath


def add_cve_front_matter(path_to_repo: str, data: dict) -> None:
    if data['id'] is None:
        raise Exception("cve id not defined in front matter")
    exists, path_to_cve = check_cve_exists(path_to_repo, data['id'])
    if exists:
        # if file exists, parse existing data and overwrite file
        with open(path_to_cve, 'r') as file:
            file_str = file.read()
            ex_data, advisory = parse_md(file_str)
            file.close()
        del data['id']
        for k, v in data.items():
            for el in v:
                ex_data.setdefault(k, []).append(el)
            if len(ex_data[k]) > 1:
                ex_data[k] = dedupe_sort(ex_data[k])
        write_md(path_to_cve, ex_data, advisory, file_str)
    else:
        # if not exist, generate new file
        compile_cve(path_to_repo, data)


def write_md(
        filepath: AnyStr,
        front_matter: Dict,
        markdown: Optional[AnyStr] = '',
        prev_file_str: Optional[AnyStr] = ''
) -> bool:
    """Writes front matter & markdown to a given filepath.

    Skips file write operation if previous file content (passed in as string) is unchanged.

    Returns:
        True or False whether file write occurred."""

    write_str = "---\n"
    write_str += object_to_yaml_str(front_matter)
    write_str += "---\n"
    if markdown != '':
        write_str += f"{markdown}\n"
    # exit without IO operation if no changes in file content
    if prev_file_str != '' and write_str == prev_file_str:
        return False
    with open(filepath, 'w+') as file:
        file.seek(0)
        file.write(write_str)
        file.truncate()
        file.close()
        return True


def parse_md(content: str) -> (dict, str):
    split = content.split('\n---')
    if len(split) < 2:
        raise Exception("error with triple dashes separating front matter")

    try:
        front_matter = yaml.load(split[0], Loader=yaml.Loader)
    except yaml.YAMLError as e:
        raise Exception("error loading front matter YAML")

    markdown = split[1].strip()

    return front_matter, markdown


def check_cve_exists(path_to_repo: str, cve: str) -> (bool, str):
    path_to_cve = os.path.join(cve_sequence_dir(os.path.join(path_to_repo, 'cve'), cve), f"{cve}.md")
    return os.path.exists(path_to_cve), path_to_cve


def cve_sequence_dir(path_to_cves: str, cve: str) -> str:
    split = cve.split("-")
    year_dir = "{}".format(split[1])
    sequence_dir = "{}xxx/".format(split[2][:-3])
    return os.path.join(path_to_cves, year_dir, sequence_dir)


def scantree(p, ext):
    # Recursively yield DirEntry objects for given directory
    for entry in os.scandir(p):
        if entry.is_dir(follow_symlinks=False):
            yield from scantree(entry.path, ext)
        elif entry.name.endswith(ext):
            yield entry


def counttree(p: str, ext: str) -> int:
    count = 0
    for entry in os.scandir(p):
        if entry.is_dir(follow_symlinks=False):
            count += counttree(entry.path, ext)
        elif entry.name.endswith(ext):
            count += 1
    return count


def search_walk(search_path, cve):
    for p, d, f in os.walk(search_path):
        for file in f:
            if file.endswith("{}.md".format(cve)):
                return os.path.join(p, file)
    raise ValueError("{}.md does not exist".format(cve))


def object_to_yaml_str(obj, options=None):
    if options is None:
        options = {}
    string_stream = StringIO()
    y = yaml.YAML()
    y.indent(mapping=2, sequence=4, offset=4)
    y.dump(obj, string_stream, **options)
    output_str = string_stream.getvalue()
    string_stream.close()
    return output_str

