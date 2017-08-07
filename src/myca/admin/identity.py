import datetime

from flask_admin import expose
from flask_admin.form import rules
from flask_admin.model.template import macro
from flask_admin.model.fields import InlineFieldList
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


class IdentityView(ModelView):
    column_list = [
        'issuer',
        'name',
        'status',
    ]
    list_template = 'admin/identity_list.html'
    details_template = 'admin/identity_details.html'
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
        'san_dns_names': InlineFieldList(fields.StringField('DNS', [validators.HostnameValidation()]),
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
        data = x509.CertData(form.data)

        if data.issuer:
            pair = models.Pair(*x509.issue_certificate(data, data.issuer.pair.as_tuple))
        else:
            pair = models.Pair(*x509.issue_certificate(data))

        model.pair = pair
        model.name = data.subj_cn

    @expose('/reissue/')
    def reissue_view(self):
        pass

    @expose('/history/')
    def history_view(self):
        pass
