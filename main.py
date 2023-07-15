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
        "name": Variant('s', "example.com"),
        "id": Variant('s', "example.com"),
    }
    user = {
        "id": Variant('ay', b"123abdsacddw"),
        "name": Variant('s', "user@example.com"),
        "display_name": Variant('s', "User 1"),
    }
    cred_params = [
        {"type": Variant('s', "public-key"), "alg": Variant('x', -7)},
        {"type": Variant('s', "public-key"), "alg": Variant('x', -257)},
        {"type": Variant('s', "public-key"), "alg": Variant('x', -8)},
    ]
    client_data = json.dumps({
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(secrets.token_bytes(16))
                           .rstrip(b'=').decode('ascii'),
        "origin": "https://example.com",
    })
    options = {}
    rsp = await interface.call_make_credential(
        rp, user, cred_params, client_data, options)
    print(rsp)
    # await bus.wait_for_disconnect()


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())


if __name__ == "__main__":
    main()
