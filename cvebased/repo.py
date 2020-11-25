from ruamel import yaml
import os


def compile_researcher(path_to_repo, data):
    filepath = os.path.join(path_to_repo, 'researcher', f"{data['alias']}.md")

    # move bio from yaml field to markdown content
    markdown = ''
    if 'bio' in data:
        markdown = data.pop('bio')

    write_md(filepath, data, markdown)

    return filepath


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


def parse_md(content):
    split = content.split('\n---')
    if len(split) < 2:
        raise Exception("error with triple dashes separating front matter")

    try:
        front_matter = yaml.load(split[0], Loader=yaml.Loader)
    except yaml.YAMLError as e:
        raise Exception("error loading front matter YAML")

    markdown = split[1].strip()

    return front_matter, markdown


def cve_sequence_dir(base_path, cve):
    split = cve.split("-")
    year_dir = "{}".format(split[1])
    sequence_dir = "{}xxx/".format(split[2][:-3])
    return os.path.join(base_path, year_dir, sequence_dir)


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
