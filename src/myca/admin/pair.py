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
    column_filters = ['identity_id']
    list_template = 'admin/pair_list.html'
    details_template = 'admin/pair_details.html'

    def is_visible(self):
        return False

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
