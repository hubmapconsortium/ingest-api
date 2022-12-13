# Routes

These are the Blueprint MSAPI endpoints (flask routes).

In general, one `theme` should be represented in one Python package.
For example, the authentication endpoints (login and logout) are in the `routes.auth`
package.

In general you add this code to the Blueprint file (`__init__.py` of a package under 'routes').

In this example we are using 'routes.auth' and showing the 'login' route.
```flask
from flask import Blueprint, current_app
import logging

auth_blueprint = Blueprint('auth', __name__)
logger: logging.Logger = logging.getLogger(__name__)

@auth_blueprint.route('/login')
```

Since the `app` variable is only available in `app.py` you should use `flask.current_app` (above import) in the route file.

Also note that the `logger` will inherit the attributes defined in `app.py`.
Specifying it in this manner allows logger configuration to be established in only one place.

The `auth_blueprint` is the thing that you will import and register as a Blueprint in the `app.py` file.
```flask
from routes.auth import auth_blueprint

app = Flask(...)

app.register_blueprint(auth_blueprint)
```

At this point the routes (MSAPI endpoints) in the Blueprint file will be available
to the application.

For more information about Flask Blueprints please see [this](https://exploreflask.com/en/latest/blueprints.html).
