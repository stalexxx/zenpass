# Recovery model

The client creates a random high-entropy recovery key and uses it to wrap `AccountKey` independently of the master-password wrapper. The recovery key is shown once, verified by a confirmation challenge, and never stored or transmitted in plaintext.

Recovery unlocks the account key and authorizes replacement of password-authentication material. It does not allow support staff or the backend to decrypt the vault. Every recovery reset revokes existing sessions and devices unless explicitly re-enrolled by the user.

