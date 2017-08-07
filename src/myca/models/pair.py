import datetime

from sqlalchemy.schema import UniqueConstraint

from .db import db
from myca import x509


class Pair(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    identity_id = db.Column(db.Integer, db.ForeignKey('identity.id'), nullable=False)
    identity = db.relationship('Identity', backref=db.backref('pairs', lazy='dynamic', cascade='all, delete-orphan'))

    issued_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    cert = db.Column(db.Binary, nullable=False)
    key = db.Column(db.Binary, nullable=False)

    __table_args__ = (
        UniqueConstraint('identity_id', 'issued_at', name='_identity_issued_at_uc'),
    )

    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    def __repr__(self):
        return '<Pair {}>'.format(self.id)

    def __str__(self):
        return '{} @ {}'.format(self.identity, self.issued_at)

    @property
    def cert_str(self):
        return self.cert.decode('ascii')

    @property
    def key_str(self):
        return self.key.decode('ascii')

    @property
    def cert_text(self):
        return x509.get_certificate_text(self.cert)

    @property
    def as_tuple(self):
        return self.cert, self.key
