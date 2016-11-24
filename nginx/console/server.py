# virtualenv -p python3.5 /services/console/.venv
# source /services/console/.venv/bin/activate
# pip install path/to/gaas/project

import falcon

from gaas.resources.console import FileRenderer

context = {
    "endpoints": {
        "api": "https://api.moldyboot.com",
        "console": "https://console.moldyboot.com"
    },
    "webcrypto": {
        "databaseName": "GAASDatabase",
        "databaseVersion": 1,
        "objectStoreName": "GAASKeyStore"
    }
}
renderer = FileRenderer(context)

console = application = falcon.API()
console.add_route("/login", renderer.static("login.html"))
console.add_route("/console", renderer.static("console.html"))
console.add_route("/debug", renderer.static("debug.html"))
console.add_route("/scripts/{filename}", renderer.dynamic("^.+\.js$"))
console.add_route("/css/{filename}", renderer.dynamic("^.+\.css$"))
