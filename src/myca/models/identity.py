from sqlalchemy.schema import UniqueConstraint

from .db import db


class Identity(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    issuer_id = db.Column(db.Integer, db.ForeignKey('identity.id'), nullable=True)
    issuer = db.relationship('Identity', remote_side=id)

    name = db.Column(db.String(255), unique=True, nullable=False)

    __table_args__ = (
        UniqueConstraint('issuer_id', 'name', name='_issuer_name_uc'),
    )

    def __repr__(self):
        return '<Identity {}>'.format(self.name)

    def __str__(self):
        return self.name

    @property
    def pair(self):
        from . import Pair
        return self.pairs.order_by(Pair.issued_at.desc()).first()

    @pair.setter
    def pair(self, pair):
        pair.identity = self
        db.session.add(pair)
