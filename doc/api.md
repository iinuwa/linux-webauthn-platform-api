# Overview

These APIs are organized by profile and then by callers.

Profiles are groups of API methods that credential portal implementations can
adopt. The base profile MUST be implemented.

The method groups:
- Public: methods that portal clients can call, implemented by the portal frontend
- Internal, Frontend: methods that portal frontends need to provide for the backend to call
- Internal, Backend: methods that portal backends need to provide for the frontend to call

// TODO: We need some sort of discovery method for the profiles. Would getClientCapabilities suffice?


# Base profile

## Public

### `CreateCredential(credRequest CreateCredentialRequest) CreateCredentialResponse`

`credRequest`: information about the credentials to save

`CreateCredentialRequest`: one of:

    CreatePasswordCredentialRequest {
        type: "password"
        password: {
            username: String
            password: String
        }
    }

    CreatePublicKeyCredentialRequest {
        type: "publicKey"
        publicKey: {
            // WebAuthn credential attestation JSON 
            registrationRequestJson: String
        }
    }

`CreateCredentialResponse`: one of:

    CreatePasswordResponse {
        type: "password"
    }

    CreatePublicKeyResponse {
        type: "publicKey"
        registrationResponseJson: String
    }

### `CreateCredential(credRequest CreateCredentialRequest, origin String, sameOrigin bool) CreateCredentialResponse`

Same as above, except `origin` and `sameOrigin` are specified. 
Only allowed for privileged clients.

`origin`: origin string

`sameOrigin`: whether the calling context is in the same origin as its ancestors.

### `GetCredential(credRequest GetCredentialRequest) GetCredentialResponse`

`credRequest`: information about the credentials to retreive

`GetCredentialRequest`:

    options: GetCredentialOption[]

`GetCredentialOption`: one of:

    GetPasswordRequestOption {
        type: "password"
        password: {}
    }

    GetPublicKeyRequestOption {
        type: "publicKey"
        publicKey: {
            // WebAuthn credential assertion request JSON
            authenticationRequestJson: String
        }
    }

`GetCredentialResponse`: one of:

    GetPasswordCredentialResponse {
        type: "password"
    }

    GetPublicKeyCredentialRepsonse {
        type: "publicKey"
        publicKey: {
            // WebAuthn credential assertion response JSON
            authenticationResponseJson: String
        }
    }

### `GetCredential(credRequest GetCredentialRequest, origin String, sameOrigin) GetCredentialResponse`

Same as above, except `origin` and `sameOrigin` are specified. Only allowed for privileged clients.

`origin`: origin string

`sameOrigin`: whether the calling context is in the same origin as its ancestors.

### `GetClientCapabilities()`

TBD. Analogous to WebAuthn Level 3's
[`getClientCapabilities()`](https://w3c.github.io/webauthn/#sctn-getClientCapabilities) method.

## Internal, Frontend

// TODO: If the frontend decides that the thing should end (another credential
request started), any method can return "RequestCancelled"

### `GetAuthToken() AuthToken`

Used to begin an authenticated session. The returned `AuthToken` will be redeemed after the user authenticates

// TODO: Is this necessary? When I wrote this, I was thinking this would be
required to associate the initiator of a fingerprint request and the
finalizer. Can the frontend tie responses to a specific process across the
D-Bus boundary and just "know" this?

### `StartFingerprintAuthentication(callback Callback)`

Begin a prompt for fingerprint authentication. If the user successfully completes fingerprint authentication, 

### `ValidateDeviceCredential(cred) Session`

Returns an opaque `Session` object to be used in subsequent parts of the flow.

`cred`: Device PIN, or fingerprint object.

### `ListCredentials(session Session) CredentialMetadata[]`

Returns metadata for the credentials that the client knows about, filtered by the credential as appropriate.

The frontend MAY return credentials that do not match the origin given in the
`GetCredential()` backend caller SHOULD filter and sort the credentials
according to the request origin to prevent the user from phishing attacks. 

Ultimately, the user can decide if they want to use a particular—for example,
if a password is shared between multiple sites, but they have not associated the
credential with multiple origins yet—so the frontend MAY allow the user to view more credentials that do not match. (With passkeys, the request origin is
signed by the passkey, and the RP is responsible to check that the origin is
valid, so there is some protection against phishing, even if the wrong passkey
is chosen for the given request origin.)

`CredentialMetadata`

    id: String. ID of credential, to be used in `SelectCredential()`

    origin: String. Origin of credential
    // TODO: Does this need to be multiple origins?

    displayName: String. User-chosen name for the credential.

    username: String, optional. Username of credential, if any.

### `SelectCredential(session Session, id String) CompletionToken`

Send the ID of the credential that the user selected. Returns a token that can
be used to call CompleteTransaction().

### `CompleteTransaction()`

Backend is done with the request, called after `SelectCredential()`.
Frontend will continue with sending the selected result to the client.

// TODO: Is this necessary? I thought it might be useful to allow for the UI to
control window cleanup and whatnot, but maybe that can just be done at the
end of `SelectCredential()`.

### `CancelRequest()`

Cancels the current request, cleaning up any resources held by the frontend for the request.

// TODO: Does this need a reason, e.g. user cancelled, or will it always just be
user cancelled?

## Internal, Backend

### `GetCredential(origin String, types: String[])`

TODO: This needs some work. The backend needs to know the type to know what to
display. E.g. "Select a password" vs. "This will use your device credentials". 

### NotifyFingerprint()

// TODO: I don't know if this needs to be here. Maybe a callback in
StartFingerprintAuth() would be better? Or if this is needed, maybe a generic
`Notify()` method that takes a type would be better instead?

# Platform Authenticator profile

## Internal, Frontend

## Internal, Backend

# Provider profile

## Internal, Frontend

## Internal, Backend

# General Questions

Is D-Bus a secure transport, or do values need to be encrypted across D-Bus?