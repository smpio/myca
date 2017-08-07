import os

from flask import Flask
from flask_migrate import Migrate
from werkzeug.contrib.fixers import ProxyFix

from myca import config, models
from myca.admin import admin


app = Flask(__name__, template_folder='admin/templates')

app.secret_key = config.secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = config.database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if config.reverse_proxy_count:
    app.wsgi_app = ProxyFix(app.wsgi_app, num_proxies=config.reverse_proxy_count)

models.db.app = app
models.db.init_app(app)

migrate = Migrate(app, models.db, directory=os.path.join(config.app_root, 'myca', 'migrations'))

admin.init_app(app)
