# github.com/faroedev/faroe

_Documentation at [faroe.dev](https://faroe.dev)._

_This software is in active development and has only gone through minimal testing._

Faroe is a modular auth server distributed as a Go package.

```
go get github.com/faroedev/faroe
```

Some key features of the server:

1. Takes care of all the hard parts. Passwords, email address verification, sessions, rate limiting, password resets, and more.
2. Extends your existing user database instead of replacing it. Own and customize your user data. No more data synchronization between servers.
3. No direct connections to your database.
4. Only ephemeral data is stored. Less things to manage and worry about.

```ts
const result = await client.createSignup(emailAddress);
if (!result.ok) {
    console.log(result.errorCode);
    return;
}
console.log(result.signup);
window.localStorage.setItem("signup_token", result.signupToken);
```

The package has no hard dependencies. All you need is a key-value store and an email server.

```go
package main

import "github.com/faroedev/faroe"

func main() {
	server := faroe.NewServer(
		storage,
		userStore,
		logger,
		userPasswordHashAlgorithms,
		temporaryPasswordHashAlgorithm,
		cpuCount,
		faroe.RealClock,
		faroe.AllowAllEmailAddresses,
		emailSender,
		sessionConfig,
	)
}
```

Only password authentication is supported. Support for passkeys and 2FA are planned but there are no immediate plans to add social login (e.g. Sign in with Google).
