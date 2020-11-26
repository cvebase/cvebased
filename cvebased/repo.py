from ruamel import yaml
import os
from cvebased.common import dedupe_sort


def compile_researcher(path_to_repo, data):
    filepath = os.path.join(path_to_repo, 'researcher', f"{data['alias']}.md")
    # move bio from yaml field to markdown content
    markdown = ''
    if 'bio' in data:
        markdown = data.pop('bio')
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
        markdown = data.pop('advisory')
    write_md(filepath, data, markdown)
    return filepath


def add_cve_front_matter(path_to_repo: str, data: dict) -> None:
    if data['id'] is None:
        raise Exception("cve id not defined in front matter")
    exists, path_to_cve = check_cve_exists(path_to_repo, data['id'])
    if exists:
        # if file exists, parse existing data and overwrite file
        with open(path_to_cve, 'r') as file:
            ex_data, advisory = parse_md(file.read())
            file.close()
        del data['id']
        for k, v in data.items():
            for el in v:
                ex_data.setdefault(k, []).append(el)
            if len(ex_data[k]) > 1:
                ex_data[k] = dedupe_sort(ex_data[k])
        write_md(path_to_cve, ex_data, advisory)
    else:
        # if not exist, generate new file
        compile_cve(path_to_repo, data)


def write_md(filepath, front_matter, markdown=''):
    with open(filepath, 'w+') as file:
        file.seek(0)
        file.write("---\n")
        y = yaml.YAML()
        y.indent(mapping=2, sequence=4, offset=4)
        y.dump(front_matter, file)
        file.write("---\n")
        if markdown != '':
            file.write("{}\n".format(markdown))
        file.truncate()
        file.close()


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
