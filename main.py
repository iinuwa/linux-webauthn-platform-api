import asyncio
import base64
import json
import secrets

from dbus_next.aio import MessageBus
from dbus_next import Variant


async def run():
    bus = await MessageBus().connect()

    with open('xyz.iinuwa.credentials.CredentialManager.xml', 'r') as f:
        introspection = f.read()

    proxy_object = bus.get_proxy_object('xyz.iinuwa.credentials.CredentialManager',
                                        '/xyz/iinuwa/credentials/CredentialManager',
                                        introspection)

    interface = proxy_object.get_interface(
        'xyz.iinuwa.credentials.CredentialManager1')

    rp = {
        "name": "example.com",
        "id": "example.com",
    }
    user = {
        "id": b"123abdsacddw",
        "name": "user@example.com",
        "display_name": "User 1",
    }
    cred_params = [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257},
        {"type": "public-key", "alg": -8},
    ]
    client_data = json.puts({
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip('='),
        "origin": "https://example.com",
    })
    rsp = await interface.call_make_credential(rp, user, cred_params, client_data, options)
    print(rsp)
    await bus.wait_for_disconnect()


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())


if __name__ == "__main__":
    main()
