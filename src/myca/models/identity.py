from sqlalchemy.schema import UniqueConstraint

from myca import x509
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

    @property
    def pair_error(self):
        try:
            ca_cert_chain_data = []
            issuer = self.issuer
            while issuer:
                ca_cert_chain_data.append(issuer.pair.cert)
                issuer = issuer.issuer
            if not ca_cert_chain_data:
                return
            x509.verify_certificate_chain(self.pair.cert, ca_cert_chain_data)
        except x509.InvalidCertificate as e:
            return str(e)
