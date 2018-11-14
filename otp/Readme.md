2FA config is a JSON hash that has the following structure.

```json
{
  "Namespace/Ident": {
    "Operation": ["array", "of", "tokens"]
  }
}
```

Example: If you wish to Protect Nomad Job called "hello-world"
- Allow Get
- A new deployment should have two stakeholders's OTP
- Stop a Job could do with just one

The totp config would look like:

```json
{
  "hello-world": {
    "*": [],
    "POST": ["GA4DGMQ4TKZMFTDSNBUDEMZYMYYA", "GA4DGMQ4TKZMdedeqeSNBUDEMZYMYYA"],
    "DELETE": ["GA4DGMQ4TKZMFTDSNBUDEMZYMYYA"]
  }
}
```

Verification library is independent of Nomad and Tessellate and can be utilized for any purpose which can leverage the same configuration structure.

Example usage:

```config
{
  "rules": {
    "/missing": {
      "key1": ["token1"],
      "key2": ["token2"],
      "*": []
    }
  }
}
````

```go
b, err := ioutil.ReadAll(configFile)
if err != nil {
  panic(err)
}

rules := map[string]map[string][]string{}
if err := json.Unmarshal(b, &rules); err != nil {
  panic(err)
}

tfa := ts2fa.New(&ts2fa.Ts2FAConf{
  Rules:     rules
})


p := NewPayload("/missing", "key1", "12345")
valid, err := tfa.Verify(p)
if err != nil {
  panic(err)
}
```
