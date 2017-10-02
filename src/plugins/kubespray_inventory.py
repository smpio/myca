import json
import functools

from flask import Response, request, abort, flash, redirect
from flask_admin.actions import action
from flask_admin.helpers import get_redirect_target

from myca import models, admin, x509
from myca.app import app

node_prefix = 'system:node:'


@app.route('/kubespray/<ca_name>.json')
def kubespray_inventory(ca_name):
    ca = models.Identity.query.filter_by(name=ca_name, issuer=None).first()
    if ca is None:
        return abort(404)

    global_vars = {
        'ca_cert': ca.pair.cert.decode('ascii'),
    }

    host_vars = {}
    for node in models.Identity.query.filter_by(issuer=ca).filter(models.Identity.name.like(node_prefix + '%')):
        name = node.name[len(node_prefix):]
        host_vars[name] = {
            'node_cert': node.pair.cert.decode('ascii'),
            'node_key': node.pair.key.decode('ascii'),
        }

    master_vars = {}
    master = models.Identity.query.filter_by(issuer=ca, name='system:master').first()
    if master is not None:
        master_vars['service_account_key'] = master.pair.key.decode('ascii')

    # etcd_vars = {}
    # etcd = models.Identity.query.filter_by(issuer=ca, name='system:etcd').first()
    # if etcd is not None:
    #     etcd_vars['etcd_cert'] = etcd.pair.cert.decode('ascii')
    #     etcd_vars['etcd_key'] = etcd.pair.key.decode('ascii')

    return render({
        'all': {
            'vars': global_vars,
        },
        'kube-master': {
            'vars': master_vars,
        },
        # 'etcd': {
        #     'vars': etcd_vars,
        # },
        '_meta': {
            'hostvars': host_vars,
        },
    })


def render(data):
    try:
        indent = int(request.args.get('indent', 0))
    except ValueError:
        return abort(400)

    if indent:
        body = json.dumps(data, indent=indent)
    else:
        body = json.dumps(data, separators=(',', ':'))

    return Response(body, mimetype='application/json')


def patch():
    for view in admin.admin._views:
        if isinstance(view, admin.IdentityView):
            view.set_master_action = action('set_master', 'Set as master')(functools.partial(set_master_action, view))
            view.init_actions()


def set_master_action(view, ids):
    nodes = models.Identity.query.filter(models.Identity.id.in_(ids))
    for node in nodes:
        info = x509.load_certificate_info(node.pair.as_tuple, reissue=True)

        dns_names = set(info.san_dns_names)
        ips = set(info.san_ips)

        dns_names.add('k8s.smp.iop.su')
        dns_names.add('kubernetes')
        dns_names.add('kubernetes.default')
        dns_names.add('kubernetes.default.svc')
        dns_names.add('kubernetes.default.svc.cluster.local')
        dns_names.add('localhost')
        ips.add('10.3.0.1')
        ips.add('127.0.0.1')

        info.san_dns_names = sorted(dns_names)
        info.san_ips = sorted(ips)

        if node.issuer:
            pair = models.Pair(*x509.issue_certificate(info, node.issuer.pair.as_tuple))
        else:
            pair = models.Pair(*x509.issue_certificate(info))

        node.pair = pair

    view.session.commit()
    return_url = get_redirect_target() or view.get_url('.index_view')
    flash('The identities reissued as master', 'success')
    return redirect(return_url)


patch()
