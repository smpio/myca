from flask import request, flash, redirect
from flask_admin import expose
from flask_admin.helpers import get_redirect_target

from myca import models
from .base import ModelView


class PairView(ModelView):
    can_create = False
    can_delete = False
    can_edit = False

    column_list = ['issued_at']
    list_template = 'admin/pair_list.html'
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

    @expose('/revert/', methods=['POST'])
    def revert_view(self):
        old_pair = self.get_one(request.values.get('id'))
        new_pair = models.Pair(old_pair.cert, old_pair.key)
        new_pair.identity_id = old_pair.identity_id
        self.session.add(new_pair)
        self.session.commit()
        return_url = get_redirect_target() or self.get_url('identity.index_view')
        flash('The certificate was successfully reverted', 'success')
        return redirect(return_url)
