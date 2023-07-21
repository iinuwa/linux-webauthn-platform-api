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
