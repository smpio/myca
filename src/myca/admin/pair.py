from flask import request

from myca import models
from .base import ModelView


class PairView(ModelView):
    can_create = False
    can_delete = False
    can_edit = False

    column_list = ['issued_at']
    details_template = 'admin/pair_details.html'

    def is_visible(self):
        return False

    def get_query(self):
        query = super().get_query().order_by(models.Pair.issued_at.desc())
        identity_id = request.args.get('identity_id')
        if identity_id:
            query = query.filter_by(identity_id=identity_id)
        return query

    def get_count_query(self):
        query = super().get_count_query()
        identity_id = request.args.get('identity_id')
        if identity_id:
            query = query.filter_by(identity_id=identity_id)
        return query
