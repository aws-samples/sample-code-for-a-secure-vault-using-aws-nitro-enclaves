# User Guide

## Deployment

For instructions on deploying the solution, visit the [Deployment Guide](./deployment.md). Once deployment is complete, check the [Post Deployment Guide](./post-deployment.md) to create a vault.

---

## Interacting with Vaults

[Swagger UI](https://github.com/swagger-api/swagger-ui) is available after deployment at `https://<API Gateway Endpoint>/v1/swagger`.

The Nitro Enclaves Vault solution exposes a RESTful API for interacting with vaults aligned to HTTP methods.

---

### Create vault (`POST /v1/vaults`)

This endpoint creates a new user vault by calling `kms:GenerateDataKeyPairWithoutPlaintext` and using the returned public key to encrypt the optional payload data.

##### Sample Request

```shell
POST /v1/vaults HTTP/1.1
Content-Type: application/json
Content-Length: 81

{
  "first_name": "Test",
  "last_name": "User",
  "ssn9": "123456789",
  "dob": "2020-01-01"
}
```

##### Sample Response

```shell
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 17:18:17 GMT
Content-Type: application/json
Content-Length: 37
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Expires: 0
Pragma: no-cache

{"id":"v_01HV1XW70Q03PHK892JFQAY0Z5"}
```

---

### Get user vault (`GET /v1/vaults/<vault_id>`)

This endpoint returns whether attributes are included within the vault or not.

##### Sample Request

```shell
GET /v1/vaults/<vault_id>?fields=first_name,last_name,email,middle_name,ssn9,ssn4,dob HTTP/1.1
```

##### Sample Response

```shell
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 18:06:11 GMT
Content-Type: application/json
Content-Length: 105
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Expires: 0
Pragma: no-cache

{"first_name":true,"last_name":true,"email":false,"middle_name":false,"ssn9":true,"ssn4":true,"dob":true}
```

---

### Update vault (`PATCH /v1/vaults/<vault_id`>)

This endpoint will overwrite existing attributes contained within the vault. This endpoint returns an empty response.

##### Sample Request

```shell
PATCH /v1/vaults/<vault_id> HTTP/1.1
Content-Type: application/json
Content-Length: 82

{
  "first_name": "Test",
  "last_name": "User",
  "ssn9": "123456789",
  "dob": "2022-01-01"
}
```

##### Sample Response

```shell
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 18:36:30 GMT
Content-Type: application/json
Content-Length: 2
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Expires: 0
Pragma: no-cache

{}
```

---

### Delete vault (`DELETE /v1/vaults/<vault_id>`)

This endpoint will delete specific attributes or the entire user vault. This endpoint returns an empty response.

##### Sample Request (specific attributes)

```shell
DELETE /v1/vaults/<vault_id> HTTP/1.1
Content-Type: application/json
Content-Length: 20

{
  "fields": ["ssn9"]
}
```

##### Sample Response (specific attributes)

```shell
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 18:36:30 GMT
Content-Type: application/json
Content-Length: 2
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Expires: 0
Pragma: no-cache

{}
```

##### Sample Request (all attributes)

```shell
DELETE /v1/vaults/<vault_id> HTTP/1.1
Content-Type: application/json
Content-Length: 20

{
  "delete_all": true
}
```

##### Sample Response  (all attributes)

```shell
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 18:36:30 GMT
Content-Type: application/json
Content-Length: 2
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Expires: 0
Pragma: no-cache

{}
```

---

### Decrypt user vault (`POST /v1/vaults/<vault_id>/decrypt`)

This endpoint communicates with the internal Network Load Balancer endpoint to decrypt attributes securely from within the Nitro Enclaves. The API supports three attributes in the request:

* `fields`: an array of string attributes to decrypt
* `reason`: a string reason for the decrypt request that gets logged
* `expressions`: a object of [Common Expression Language](https://cel.dev/) (CEL) expressions to execute against the decrypted attributes (more details below)

##### Sample Request

```shell
POST /v1/vaults/<vault_id>/decrypt
Content-Type: application/json
Content-Length: 116

{
  "fields": [
    "first_name",
    "last_name",
    "dob",
    "ssn4"
  ],
  "reason": "user validation",
  "expressions": {
    "age": "date(dob).age()"
  }
}
```

##### Sample Response

```shell
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 20:46:52 GMT
Content-Type: application/json
Content-Length: 82
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Expires: 0
Pragma: no-cache

{"age":37,"dob":"1986-01-01","first_name":"Test","last_name":"User","ssn4":"6789"}
```

---

## CEL Expressions

The Decrypt API supports the following expressions functions through the [Common Expression Language](https://cel.dev/) (CEL).

> Common Expression Language (CEL) is a general-purpose expression language designed to be fast, portable, and safe to execute. You can use CEL on its own or embed it into a larger product. CEL is a great fit for a wide variety applications, from routing remote procedure calls (RPCs) to defining security policies. CEL is extensible, platform independent, and optimized for compile-once/evaluate-many workflows.

#### contains

Returns true if the target contains the provided argument. The actual behavior depends mainly on the type of the target.

```
[1, 2, 3].contains(1) == true
{"a": 1, "b": 2, "c": 3}.contains("a") == true
"abc".contains("b") == true
b"abc".contains(b"c") == true
```

#### size

Calculates the size of either the target, or the provided arguments depending on how the function is called. If called as a method, the target will be used. If called as a function, the first argument will be used.

```
size([1, 2, 3]) == 3
```

#### has

Returns true if the provided argument can be resolved. This function is useful for checking if a property exists on a type before attempting to resolve it. Resolving a property that does not exist will result in a [`ExecutionError::NoSuchKey`] error.

```
has(foo.bar.baz)
```

#### map

Maps the provided list to a new list by applying an expression to each input item.

```
[1, 2, 3].map(x, x * 2) == [2, 4, 6]
```

#### filter

Filters the provided list by applying an expression to each input item and including the input item in the resulting list, only if the expression returned true.

```
[1, 2, 3].filter(x, x > 1) == [2, 3]
```

#### all

Returns a boolean value indicating whether every value in the provided list or map met the predicate defined by the provided expression. If called on a map, the predicate is applied to the map keys.

```
[1, 2, 3].all(x, x > 0) == true
[{1:true, 2:true, 3:false}].all(x, x > 0) == true
```

#### max

Returns the maximum value from a list or arguments.

```
max([1, 2, 3]) == 3
```

#### startsWith

Returns true if a string starts with another string.

```
"abc".startsWith("a") == true
```

#### duration

Duration parses the provided argument into a [`Value::Duration`] value. The argument must be string, and must be in the format of a duration.

* `1h` parses as 1 hour
* `1.5h` parses as 1 hour and 30 minutes
* `1h30m` parses as 1 hour and 30 minutes
* `1h30m1s` parses as 1 hour, 30 minutes, and 1 second
* `1ms` parses as 1 millisecond
* `1.5ms` parses as 1 millisecond and 500 microseconds
* `1ns` parses as 1 nanosecond
* `1.5ns` parses as 1 nanosecond (sub-nanosecond durations not supported)

#### timestamp

Timestamp parses the provided argument into a [`Value::Timestamp`] value.

```
timestamp("2024-04-09T18:58:44Z")
```

#### string

Performs a type conversion on the target. The following conversions are currently supported:

* `string` - Returns a copy of the target string.
* `timestamp` - Returns the timestamp in RFC3339 format.
* `duration` - Returns the duration in a string formatted like "72h3m0.5s".
* `int` - Returns the integer value of the target.
* `uint` - Returns the unsigned integer value of the target.
* `float` - Returns the float value of the target.
* `bytes` - Converts bytes to string using from_utf8_lossy.

```
string("1.2") == 1.2
```

#### double

Performs a type conversion on the target.

```
double("1.2") == 1.2
```

#### exists

Returns a boolean value indicating whether a or more values in the provided list or map meet the predicate defined by the provided expression. If called on a map, the predicate is applied to the map keys.

```
[1, 2, 3].exists(x, x > 0) == true
[{1:true, 2:true, 3:false}].exists(x, x > 0) == true
```

#### exists_one

Returns a boolean value indicating whether only one value in the provided list or map meets the predicate defined by the provided expression. If called on a map, the predicate is applied to the map keys.

```
[1, 2, 3].exists_one(x, x > 0) == false
[1, 2, 3].exists_one(x, x == 1) == true
[{1:true, 2:true, 3:false}].exists_one(x, x > 0) == false
```

#### int

Performs a type conversion on the target.

```
int("1") == 1
```

#### uint

Performs a type conversion on the target.

```
uint("1") == 1
```

#### is_empty

Returns true if the string is empty.

```
"test".is_empty() == false
"".is_empty() == true
```

#### to_lowercase

Returns a lowercase string.

```
"TEST".to_lowercase() == "test"
```

#### to_uppercase

Returns an uppercase string.

```
"test".to_uppercase() == "TEST"
```

#### hmac_sha256

Computes a SHA256 hash of the value.

```
"test".hmac_sha256() == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

#### hmac_sha384

Computes a SHA384 hash of the value.

```
"test".hmac_sha384() == "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
```

#### hmac_sha512

Computes a SHA512 hash of the value.

```
"test".hmac_sha512() == "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
```

#### hex_encode

Encodes a string as hexidecimal.

```
"test".hex_encode() == "74657374"
```

#### hex_decode

Decodes a hexidecimal string.

```
"74657374".hex_decode() == "test"
```

#### base64_encode

Base64 encodes a string.

```
"test".base64_encode() == "dGVzdA=="
```

#### base64_decode

Base64 decodes a string.

```
"dGVzdA==".base64_decode() == "test"
```

#### date

Converts a string into an internal date representation.

```
date("2024-04-09") == "2024-04-09T00:00:00Z"
```

#### today_utc

Returns today's date in UTC.

```
today_utc() == "2024-04-09T00:00:00Z"
```

#### age

Returns the number of years from a given date.

```
date("1986-12-11").age() == 37
```
