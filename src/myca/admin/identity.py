import datetime

from flask import request, flash, redirect
from flask_admin import expose
from flask_admin.form import rules
from flask_admin.helpers import get_redirect_target, get_form_data
from flask_admin.model.template import macro
from flask_admin.model.fields import InlineFieldList
import wtforms
from wtforms import fields
from wtforms import validators

from myca import x509, models
from .base import ModelView

required = [validators.DataRequired()]


def default_since():
    return datetime.datetime.now()


def default_till():
    since = default_since()
    return since.replace(year=since.year + 1)


class ImportForm(wtforms.Form):
    cert = fields.TextAreaField('Certificate PEM data', validators=required)
    key = fields.TextAreaField('Private key PEM data', validators=required)


class IdentityView(ModelView):
    column_list = [
        'issuer',
        'name',
        'status',
    ]
    list_template = 'admin/identity_list.html'
    column_formatters = {
        'status': macro('render_status'),
    }

    form_excluded_columns = [
        'name',
        'issues',
        'pairs',
    ]

    form_extra_fields = {
        'subj_cn': fields.StringField('CN', description='Common Name', validators=required),
        'subj_c': fields.StringField('C', description='Country'),
        'subj_o': fields.StringField('O', description='Organization'),
        'subj_ou': fields.StringField('OU', description='Organizational Unit'),
        'subj_dnq': fields.StringField('', description='Distinguished name qualifier'),
        'subj_st': fields.StringField('ST', description='State or province name'),
        'subj_sn': fields.StringField('', description='Serial number'),

        'cert_validate_since': fields.DateTimeField('Valid since', description='Not valid before', validators=required,
                                                    default=default_since),
        'cert_validate_till': fields.DateTimeField('Valid till', description='Not valid after', validators=required,
                                                   default=default_till),
        'cert_ca_path_length': fields.IntegerField('CA path length', default=0),

        'san_ips': InlineFieldList(fields.StringField('IP', [validators.IPAddress()]),
                                   'IP', description='IP address'),
        'san_dns_names': InlineFieldList(fields.StringField('DNS'),
                                         'DNS', description='DNS names'),

        'ku_web_server_auth': fields.BooleanField('Web server auth', description='TLS Web Server Authentication'),
        'ku_web_client_auth': fields.BooleanField('Web client auth', description='TLS Web Client Authentication'),

        'key_size': fields.IntegerField('Size', default=4096),
        'key_public_exponent': fields.IntegerField('Public exponent', default=65537),
    }

    form_rules = [
        rules.Field('issuer'),
        rules.FieldSet([
            'cert_validate_since',
            'cert_validate_till',
            'cert_ca_path_length',
        ], 'Certificate settings'),
        rules.FieldSet([
            'subj_cn',
            'subj_c',
            'subj_o',
            'subj_ou',
            'subj_dnq',
            'subj_st',
            'subj_sn',
        ], 'Subject'),
        rules.FieldSet([
            'san_ips',
            'san_dns_names',
        ], 'Subject Alternative Names'),
        rules.FieldSet([
            'ku_web_server_auth',
            'ku_web_client_auth',
        ], 'Key Usage'),
        rules.FieldSet([
            'key_size',
            'key_public_exponent',
        ], 'Key Settings'),
    ]

    def create_model(self, *args, **kwargs):
        with self.session.no_autoflush:
            return super().create_model(*args, **kwargs)

    def on_model_change(self, form, model, is_created):
        data = x509.CertInfo(form.data)

        if data.issuer:
            pair = models.Pair(*x509.issue_certificate(data, data.issuer.pair.as_tuple))
        else:
            pair = models.Pair(*x509.issue_certificate(data))

        model.pair = pair
        model.name = data.subj_cn

    @expose('/reissue/', methods=['POST'])
    def reissue_view(self):
        model = self.get_one(request.values.get('id'))
        info = x509.load_certificate_info(model.pair.as_tuple, reissue=True)

        if model.issuer:
            pair = models.Pair(*x509.issue_certificate(info, model.issuer.pair.as_tuple))
        else:
            pair = models.Pair(*x509.issue_certificate(info))

        model.pair = pair

        return_url = get_redirect_target() or self.get_url('.index_view')
        flash('The identity certificate was successfully reissued', 'success')
        return redirect(return_url)

    def edit_form(self, obj=None):
        form = super().edit_form(obj)

        if obj:
            info = x509.load_certificate_info(obj.pair.as_tuple, reissue=True)

            for k, v in info.as_dict().items():
                field = form[k]

                if not isinstance(field, fields.FieldList):
                    field.data = v
                else:
                    for v in v:
                        field.append_entry(v)

        return form

    @expose('/details/')
    def details_view(self):
        model = self.get_one(request.values.get('id'))
        return_url = get_redirect_target() or self.get_url('.index_view')
        return redirect(self.get_url('pair.details_view', id=model.pair.id, url=return_url))

    @expose('/import/', methods=['GET', 'POST'])
    def import_view(self):
        return_url = get_redirect_target() or self.get_url('.index_view')
        form = ImportForm(get_form_data())

        if self.validate_form(form):
            pair_tuple = form.data['cert'].encode('ascii'), form.data['key'].encode('ascii')
            info = x509.load_certificate_info(pair_tuple)

            identity = models.Identity()
            identity.name = info.subj_cn

            if info.issuer_cn:
                def find_issuer():
                    for issuer in models.Identity.query.filter_by(name=info.issuer_cn):
                        cert_chain = issuer.get_cert_chain()
                        try:
                            x509.verify_certificate_chain(pair_tuple[0], cert_chain)
                        except x509.InvalidCertificate:
                            pass
                        else:
                            return issuer

                identity.issuer = find_issuer()
                if not identity.issuer:
                    flash('Failed to import identity: issuer identity not found.', 'error')
                    return redirect(return_url)

            self.session.add(identity)
            pair = models.Pair(*pair_tuple)
            pair.identity = identity
            self.session.add(pair)
            self.session.commit()
            flash('Identity was successfully imported.', 'success')
            return redirect(self.get_save_return_url(identity, is_created=True))

        return self.render('admin/identity_import.html',
                           form=form,
                           return_url=return_url)
