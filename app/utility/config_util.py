import asyncio
import logging
import pathlib
import secrets

import jinja2
import yaml

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


# Reuse a single PasswordHasher — instantiation is non-trivial and we hit this
# path on every authenticated API request.
_PASSWORD_HASHER = PasswordHasher()


CONFIG_MSG_TEMPLATE = jinja2.Template("""
Log into Caldera with the following admin credentials:
    Red:
    {%- if users.red.red %}
        USERNAME: red
        PASSWORD: {{ users.red.red }}
    {%- endif %}
        API_TOKEN: {{ api_key_red }}
    Blue:
    {%- if users.blue.blue %}
        USERNAME: blue
        PASSWORD: {{ users.blue.blue }}
    {%- endif %}
        API_TOKEN: {{ api_key_blue }}
To modify these values, edit the {{ config_path }} file and restart Caldera.
""")
LOCAL_CONF_PATH = 'conf/local.yml'
SECRET_OPTIONS = ('api_key_blue', 'api_key_red', 'crypt_salt', 'encryption_key')
HASHED_OPTIONS = ('api_key_blue', 'api_key_red')


def _is_hashed(val):
    return isinstance(val, str) and val.startswith('$argon2id$')


def verify_hash(hash_val, target):
    """
    Returns True if the argon2 hash for the target matches hash_val, False otherwise.
    Returns False for None or non-string inputs.

    NOTE: argon2 verification is intentionally CPU-heavy (~100-500ms per call).
    Callers reachable from an asyncio handler MUST use ``verify_hash_async``
    instead — otherwise every API request that carries a KEY header blocks
    the event loop and turns concurrent requests into 504 Gateway Timeouts.
    """
    if not isinstance(hash_val, str) or not isinstance(target, str):
        return False
    try:
        return _PASSWORD_HASHER.verify(hash_val, target)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


async def verify_hash_async(hash_val, target):
    """Run :func:`verify_hash` on the default executor so the asyncio loop
    is free to service other requests while argon2 does its work.
    """
    if not isinstance(hash_val, str) or not isinstance(target, str):
        return False
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, verify_hash, hash_val, target)


def hash_config_creds(config):
    """
    Hashes the red/blue API keys and any user passwords in the config dictionary.
    Modifies the configuration dictionary parameter.
    Returns True if any values were modified (hashed), False otherwise.
    """
    ph = _PASSWORD_HASHER
    any_hashed = False
    for option in HASHED_OPTIONS:
        val = config.get(option, '')

        # Skip any values that are already hashed
        if val and not _is_hashed(val):
            config[option] = ph.hash(val)
            any_hashed = True

    # Hash credentials
    for group_name, group_dict in config.get('users', dict()).items():
        for username, val in group_dict.items():
            if not _is_hashed(val):
                config['users'][group_name][username] = ph.hash(val)
                any_hashed = True

    return any_hashed


def make_secure_config():
    with open('conf/default.yml', 'r') as fle:
        config = yaml.safe_load(fle)

    for option in SECRET_OPTIONS:
        config[option] = secrets.token_urlsafe()

    config['users'] = dict(red=dict(red=secrets.token_urlsafe()),
                           blue=dict(blue=secrets.token_urlsafe()))

    # Display API keys and user credentials, then hash them
    logging.info(CONFIG_MSG_TEMPLATE.render(config_path=LOCAL_CONF_PATH, **config))
    hash_config_creds(config)

    return config


def ensure_local_config():
    """
    Checks if a local.yml config file exists. If not, generates a new local.yml file using secure random values.
    """
    local_conf_path = pathlib.Path(LOCAL_CONF_PATH)
    if local_conf_path.exists():
        return

    logging.info('Creating new secure config in %s' % local_conf_path)
    with local_conf_path.open('w') as fle:
        yaml.safe_dump(make_secure_config(), fle, default_flow_style=False)
