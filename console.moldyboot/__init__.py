import os
import pathlib
from jinja2 import Environment, FileSystemLoader

src_root = pathlib.Path(
    os.path.abspath(os.path.dirname(__file__))
).resolve()
loader = FileSystemLoader([
    str(src_root),
    str(src_root / "vendor")  # Find vendor/css/js/script as css/js/script
])
env = Environment(loader=loader)


def ensure_path_to(dst):
    try:
        dst.parent.mkdir(parents=True)
    except OSError:
        # Parent exists
        pass


def render_to_directory(dst, ctx=None, dry_run=True, overwrite=False):
    ctx = ctx or {}
    dst_root = pathlib.Path(dst).resolve()

    sources = {
        "css": ["css", "vendor/css"],
        "js": ["js", "vendor/js"],
        "html": ["html"]
    }

    # 0. Collect all source files
    files = []
    for file_type, roots in sources.items():
        for root in roots:
            for filename in (src_root / root).glob("**/*." + file_type):
                out = dst_root / file_type / filename.relative_to(src_root / root)
                if not dry_run:
                    ensure_path_to(out)
                    out = out.resolve()
                files.append((filename.resolve(), out))

    # 1. Render each to dst
    for src, dst in files:
        print("{} => {}".format(src, dst))
        tpl = env.get_template(str(src.relative_to(src_root)))
        rendered = tpl.render(ctx)
        if not dry_run:
            mode = "w" if overwrite else "x"  # x fails if dst exists
            with dst.open(mode=mode, encoding="utf-8") as dst_file:
                dst_file.write(rendered)
