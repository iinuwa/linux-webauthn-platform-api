# Flatpak portal design for credential management

User credentials

Forward-facing
- WebAuthn user agent developers (browsers) expect more from the platform.
  Spending more time incorporating Linux users will not be high on their
  priority list.

Security:
- shifting to device-bound/device-managed credentials
- Opens the door to platform authenticator
- Should provide user consent
- Enable sandboxed applications to access credentials
- Consistent interface for secrets on a device (makes for better security)
  x most users don't use multiple browsers
  x most users use the same browser across multiple operating systems
  - not for browsers only?
  x how many native desktop apps require authentication to a web service?

Usability:

Privacy:
  - should not require user to create account on third-party to have nice UI
    for credentials

# Motivation and Scope

Properly managing credentials for online services are important for user security.

A credential management API for the Linux desktop is primarily motivated by the shift to device-bound or device-managed credentials using technology like smartcards, TPMs and especially FIDO2/WebAuthn credentials. Now that device credentials are coming to consumers, it has become more important to have programmatic access to those credentials. Up until this point, users could manage credentials themselves by memorizing passwords or by copying/pasting them. But by design, device credentials cannot be easily used directly by a user; a user agent must be involved.

Browsers have taken on the user agent role for device credentials on Linux. This has jumpstarted user adoption. However, this has a few weaknesses. WebAuthn designers expect platforms (operating systems) to take on more responsibility of managing device credentials. This has benefits, such as allowing the user to use their OS credentials to authentiate both to their device and to online services. Operating systems also have privileged access to hardware, which allows them to more easily and securely connect to the hardware required to authenticate (biometric sensors, USB devices, Bluetooth/NFC radios). As native apps also adopt device credentials, it can theoretically also give them a more consistent user interface for managing credentials in different contexts. More consistency leads to better usability which leads to better user security.

These benefits cause a push to implement these features in the platform rather than the browser itself. And while browser vendors are more motivated to implement these features on more widely-used operating systems, they are less motivated to do so for Linux desktops because of the small market share that they comprise. (Though we do get some crossover from ChromeOS devices.)

Furthermore, while supporting cross-platform credentials over USB may be within the browser vendors' interest, it is unlikely that browser vendors will desire or [be able to] invest in supporting other credential transports (Bluetooth or NFC) or supporting biometric sensors or TPM-backed credentials. With a credential management API, a platform authenticator could be developed as part of the implementation to bring those capabilities to Linux users.

Besides WebAuthn push toward platform-managed credentials, the Linux desktop application ecosystem is pushing toward sandboxed applications, like Flatpak and Snap. Currently in those environments, to allow access to device credentials, the sandbox must allow access to all devices, at least for each transport (USB, Bluetooth, etc.). That is a pretty large security hole, but with a portal API and permissions design, we can provide sandboxed applications finely-grained access to device credentials without giving access to the hardware directly.

A credential management API local to the desktop also provides other benefits, like having a built-in password/passkey manager on the device (rather than requiring the user to install separate software or subscribe to another third-party service). We can also seamlessly provide access to credentials while also retaining the ability to request user's consent for applications.

For these reasons, we should.

As mentioned above, much of this is driven by device credentials. Password credentials are still largely in use, and it would be useful, for example to provide access to password credentials in the same way that device credentials are presented (similar UI components, consent dialogs, etc.). It could also unify how username/password credentials per-origin are stored 9rather than each application having its own schema in the Secret Service API, for example.) For that reason, it would be good to implement. However, it will not be worth our time if no one adopts it. If not enough apps adopt it, then even the apps that do use it will have a strange UX compared to the majority which don't, defeating the purpose of the consistent UI. However, it would still be good to leave the door open to a password credential management API. So the design of the credential management API as a whole should take that into consideration, but more attention will be paid to device credential management.

# API

The CreateCredential() method

GetCredential (IN  s     window,
               IN  a{sv} options,
               OUT o     handle);

Gets information about the user.

Supported keys in the options vardict include:

handle_token s

    A string that will be used as the last element of the handle. Must be a valid object path element. See the org.freedesktop.portal.Request documentation for more information about the handle.
reason s

    A string that can be shown in the dialog to expain why the information is needed. This should be a complete sentence that explains what the application will do with the returned information, for example: Allows your personal information to be included with recipes you share with your friends.

The following results get returned via the "Response" signal:

rp a{sv}

    Vardict with following properties:
        id s
            The relying party ID.
        name s
            The human-readable relying party name to display to the user.
user a{sv}

    Vardict with following properties:
        id ay
            The raw user ID.
        displayName s
            The human-readable name, like a nickname, for the user account. E.g. Alex Mueller.
        name s
            The human-readable name, like a username, for the user account, used for disambiguating credentials with similar displayName. E.g. alex.mueller@example.com

image s

    The uri of an image file for the users avatar photo.

IN s window:

    Identifier for the window
IN a{sv} options:

    Vardict with optional further information
OUT o handle:

    Object path for the org.freedesktop.portal.Request object representing this call

## U2F Compatibility

Some applications may currently have U2F support but not full WebAuthn support.
Because WebAuthn is compatible with U2F, we will not implement U2F Register()
and Sign() methods.

Instead, developers who wish to integrate with the Credential portal and continue to support keys that were previously registered with the U2F protocol should be
encouraged to implement support for:
- the FIDO U2F Attestation Statement Format,
- the FIDO AppID extension, and
- the FIDO AppID Exclusion extension to support.

Note that registering new U2F keys only requires support for the FIDO U2F
Attestation Statement Format.
