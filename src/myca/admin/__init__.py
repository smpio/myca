from flask_admin import Admin

from myca import models
from .identity import IdentityView
from .pair import PairView


admin = Admin(name='MyCA', url='/', template_mode='bootstrap3')
admin.add_view(IdentityView(models.Identity, models.db.session))
admin.add_view(PairView(models.Pair, models.db.session))
