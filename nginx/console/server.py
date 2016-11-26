# virtualenv -p python3.5 /services/console/.venv
# source /services/console/.venv/bin/activate
# pip install path/to/moldyboot/project

# TODO | this whole folder can be simplified down to baking
# TODO | the templates and copying them into a static folder.
# TODO | can still use bin/serve-console for testing

import falcon

from moldyboot.resources.console import FileRenderer

context = {
    "endpoints": {
        "api": "https://api.moldyboot.com",
        # https://console.moldyboot.com
        # since these are rendered on console.moldyboot, they can all be relative
        "console": ""
    },
    "webcrypto": {
        "databaseName": "MoldyDatabase",
        "databaseVersion": 1,
        "keyStoreName": "MoldyKeyStore",
        "metaStoreName": "MoldyMetaStore"
    }
}
renderer = FileRenderer(context)

console = application = falcon.API()
console.add_route("/login", renderer.static("login.html"))
console.add_route("/console", renderer.static("console.html"))
console.add_route("/_reset", renderer.static("_reset.html"))
console.add_route("/js/{filename}", renderer.dynamic("^.+\.js$"))
console.add_route("/css/{filename}", renderer.dynamic("^.+\.css$"))
