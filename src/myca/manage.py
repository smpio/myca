import logging
import pathlib
import importlib.machinery
import importlib.util

from flask_script import Manager
from flask_migrate import MigrateCommand

from myca import config
from myca.app import app

manager = Manager(app)
manager.add_command('db', MigrateCommand)


def run():
    logging.basicConfig(level='NOTSET')
    load_plugins()
    manager.run()


def load_plugins():
    if not config.plugins_dir:
        return

    path = pathlib.Path(config.plugins_dir)
    for suffix in importlib.machinery.SOURCE_SUFFIXES:
        for module_path in path.glob('*' + suffix):
            module_name = 'myca_plugins.' + module_path.stem
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)


if __name__ == '__main__':
    run()
