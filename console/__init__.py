import functools
import os
import pathlib
import texas
from jinja2 import Environment, FileSystemLoader


# ====================================================================================================== static config


jinja_options = {
    "lstrip_blocks": True,
    "trim_blocks": True
}

src_root = pathlib.Path(
    os.path.abspath(os.path.dirname(__file__))
).resolve()
sources = {
    "css": ["css", "vendor/css"],
    "js": ["js", "vendor/js"],
    "html": ["html"]
}

loader = FileSystemLoader([
    str(src_root),
    str(src_root / "vendor")  # Find vendor/css/js/script as css/js/script
])
env = Environment(loader=loader, **jinja_options)


# ====================================================================================================== static config

# ========================================================================================================== rendering


def ensure_path_to(dst, clean=False):
    if clean:
        try:
            os.rmdir(dst)
        except OSError:
            # folder doesn't exist
            pass
    try:
        dst.parent.mkdir(parents=True)
    except OSError:
        # Parent exists
        pass


def iter_sources():
    for file_type, roots in sources.items():
        for root in roots:
            for filename in (src_root / root).glob("**/*." + file_type):
                yield file_type / filename.relative_to(src_root / root)


def iter_rendered(ctx=None):
    ctx = extend_context(ctx)
    for src in iter_sources():
        tpl = env.get_template(str(src))
        rendered = tpl.render(ctx)
        yield src, rendered


def render_to_directory(dst_root, ctx=None, dry_run=True, overwrite=False):
    dst_root = pathlib.Path(dst_root)
    ctx = extend_context(ctx)
    for src, rendered in iter_rendered(ctx):
        # Drop .html suffix, collapse html/ prefix
        if src.name.endswith(".html"):
            src = pathlib.Path(*src.parts[1:])  # html/foo/name.html -> foo/name.html
        dst = dst_root / src
        if not dry_run:
            ensure_path_to(dst)
            mode = "w" if overwrite else "x"  # "x" fails if dst exists
            with dst.open(mode=mode, encoding="utf-8") as dst_file:
                dst_file.write(rendered)


# ========================================================================================================== rendering

# ==================================================================================================== context helpers


def extend_context(ctx=None):
    if ctx is None:
        ctx = {}
    for file_type in ["css", "js", "html"]:
        ctx[file_type + "_file"] = functools.partial(url_file, file_type=file_type)
    return ctx


def url_file(name, file_type):
    if str(name).endswith("." + file_type):
        name = name[:1 + len(file_type)]
    return "/{type}/{name}.{type}".format(name=name, type=file_type)


# ==================================================================================================== context helpers

# ============================================================================================================ context

context = texas.Context()
global_context = context.include("global")
global_context.update({
    "endpoints": {
        "api": None,
        "console": None
    },
    "webcrypto": {
        "databaseName": "MoldyDatabase",
        "databaseVersion": 1,
        "keyStoreName": "MoldyKeyStore",
        "metaStoreName": "MoldyMetaStore"
    }
})

production_context = context.include("global", "production")
production_context["endpoints.api"] = "https://api.moldyboot.com"
production_context["endpoints.console"] = ""


local_context = context.include("global", "local")
local_context["endpoints.api"] = "http://127.0.0.1:8010"
local_context["endpoints.console"] = "http://127.0.0.1:8020"


# ============================================================================================================ context
