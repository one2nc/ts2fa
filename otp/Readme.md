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
