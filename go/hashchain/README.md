To try it:
```bash
go run hashchain.go [args]
```

 See usage with `--help`.

 First generate a new key using `genkey`.

 Then create and sign a new chains and its seeds using `sign`.

 Then you can create proofs for values smaller than you initial value using `create` and verify it using `verify`.

 Currently we only verify that the value is smaller or equal to the signed initial value.


 TODO: implement the nice range features and the rest that the complement chain enables us to do.
