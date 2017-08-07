import logging

from flask_script import Manager
from flask_migrate import MigrateCommand

from myca.app import app

manager = Manager(app)
manager.add_command('db', MigrateCommand)


def run():
    logging.basicConfig(level='NOTSET')
    manager.run()


if __name__ == '__main__':
    run()
