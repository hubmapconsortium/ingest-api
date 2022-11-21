# app_utils

This package contains packages containing functions that were originally
taken from `app.py`.

In distributing the application among Blueprints (rather than in a single file)
there was a need to place these functions in a place where the original `app.py`
as well as the Blueprint files (found in `routes.*`) could all reach them.

If you move some endpoints/routes out of `app.py` and find a dependence on
some function, you should put it here, but only if routes in `app.py` and other
Blueprint files depend on it. If the function is specific to a route or a
collection of routes that are in one package (e.g., one `routes.*`) then
please just put the function with the Blueprint.
