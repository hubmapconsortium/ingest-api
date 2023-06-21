from flask import Blueprint, redirect, request, session, current_app
from globus_sdk import AccessTokenAuthorizer, AuthClient, ConfidentialAppAuthClient
import json
import logging

auth_blueprint = Blueprint('auth', __name__)
logger: logging.Logger = logging.getLogger(__name__)

# Endpoints for UI Login and Logout


# Redirect users from react app login page to Globus auth login widget then redirect back
@auth_blueprint.route('/login')
def login():
    # redirect_uri = url_for('login', _external=True)
    redirect_uri = current_app.config['FLASK_APP_BASE_URI'] + 'login'

    confidential_app_auth_client =\
        ConfidentialAppAuthClient(current_app.config['APP_CLIENT_ID'],
                                  current_app.config['APP_CLIENT_SECRET'])
    confidential_app_auth_client.oauth2_start_flow(redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:
        params: dict = {"scope": "openid profile email"
                                 " urn:globus:auth:scope:transfer.api.globus.org:all"
                                 " urn:globus:auth:scope:auth.globus.org:view_identities"
                                 " urn:globus:auth:scope:nexus.api.globus.org:groups"
                                 " urn:globus:auth:scope:groups.api.globus.org:all"}
        auth_uri = confidential_app_auth_client.oauth2_get_authorize_url(additional_params=params)
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        auth_code = request.args.get('code')

        token_response = confidential_app_auth_client.oauth2_exchange_code_for_tokens(auth_code)

        # Get all Bearer tokens
        auth_token = token_response.by_resource_server['auth.globus.org']['access_token']
        # nexus_token = token_response.by_resource_server['nexus.api.globus.org']['access_token']
        transfer_token = token_response.by_resource_server['transfer.api.globus.org']['access_token']
        groups_token = token_response.by_resource_server['groups.api.globus.org']['access_token']
        # Also get the user info (sub, email, name, preferred_username) using the AuthClient with the auth token
        user_info = get_user_info(auth_token)

        info = {
            'name': user_info['name'],
            'email': user_info['email'],
            'globus_id': user_info['sub'],
            'auth_token': auth_token,
            # 'nexus_token': nexus_token,
            'transfer_token': transfer_token,
            'groups_token': groups_token
        }

        # Store the resulting tokens in server session
        session.update(
            tokens=token_response.by_resource_server
        )

        # Finally redirect back to the client
        json_str: str = json.dumps(info)
        return redirect(current_app.config['GLOBUS_CLIENT_APP_URI'] + '?info=' + str(json_str))


@auth_blueprint.route('/logout')
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    confidential_app_auth_client =\
        ConfidentialAppAuthClient(current_app.config['APP_CLIENT_ID'],
                                  current_app.config['APP_CLIENT_SECRET'])

    # Revoke the tokens with Globus Auth
    if 'tokens' in session:
        for token in (token_info['access_token']
            for token_info in session['tokens'].values()):
                confidential_app_auth_client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client={}'.format(current_app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(current_app.config['GLOBUS_CLIENT_APP_URI']) +
        '&redirect_name={}'.format(current_app.config['GLOBUS_CLIENT_APP_NAME']))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)


# Redirect users from the Data Ingest Board login page to Globus auth login widget then redirect back
@auth_blueprint.route('/data-ingest-board-login')
def ingest_board_login():
    redirect_uri = current_app.config['FLASK_APP_BASE_URI'] + 'data-ingest-board-login'
    confidential_app_auth_client =\
        ConfidentialAppAuthClient(current_app.config['APP_CLIENT_ID'],
                                  current_app.config['APP_CLIENT_SECRET'])
    confidential_app_auth_client.oauth2_start_flow(redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:
        params: dict = {"scope": "openid profile email"
                                 " urn:globus:auth:scope:transfer.api.globus.org:all"
                                 " urn:globus:auth:scope:auth.globus.org:view_identities"
                                 " urn:globus:auth:scope:nexus.api.globus.org:groups"
                                 " urn:globus:auth:scope:groups.api.globus.org:all"}
        auth_uri = confidential_app_auth_client.oauth2_get_authorize_url(additional_params=params)
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        auth_code = request.args.get('code')

        token_response = confidential_app_auth_client.oauth2_exchange_code_for_tokens(auth_code)

        # Get all Bearer tokens
        auth_token = token_response.by_resource_server['auth.globus.org']['access_token']
        # nexus_token = token_response.by_resource_server['nexus.api.globus.org']['access_token']
        transfer_token = token_response.by_resource_server['transfer.api.globus.org']['access_token']
        groups_token = token_response.by_resource_server['groups.api.globus.org']['access_token']
        # Also get the user info (sub, email, name, preferred_username) using the AuthClient with the auth token
        user_info = get_user_info(auth_token)

        info = {
            'name': user_info['name'],
            'email': user_info['email'],
            'globus_id': user_info['sub'],
            'auth_token': auth_token,
            # 'nexus_token': nexus_token,
            'transfer_token': transfer_token,
            'groups_token': groups_token
        }

        # Store the resulting tokens in server session
        session.update(
            ingest_board_tokens=token_response.by_resource_server
        )

        # Finally redirect back to the client
        json_str: str = json.dumps(info)
        return redirect(current_app.config['DATA_INGEST_BOARD_APP_URI'] + '?info=' + str(json_str))


@auth_blueprint.route('/data-ingest-board-logout')
def ingest_board_logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    confidential_app_auth_client =\
        ConfidentialAppAuthClient(current_app.config['APP_CLIENT_ID'],
                                  current_app.config['APP_CLIENT_SECRET'])

    # Revoke the tokens with Globus Auth
    if 'ingest_board_tokens' in session:
        for token in (token_info['access_token']
            for token_info in session['tokens'].values()):
                confidential_app_auth_client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client={}'.format(current_app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(current_app.config['DATA_INGEST_BOARD_APP_URI']) +
        '&redirect_name={}'.format(current_app.config['DATA_INGEST_BOARD_NAME']))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)


def get_user_info(token):
    auth_client = AuthClient(authorizer=AccessTokenAuthorizer(token))
    return auth_client.oauth2_userinfo()
