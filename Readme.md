# Open API validator

Given an OpenAPI 3.1 specification, verifies that HTTP requests and responses actually sent and received from a server match the spec.

For example, you can integrate the validator when testing your API to ensure that not only the API returns what you expect, but that the
requests your tests send and the responses they get conform to the spec.

Integrates with Rust [httparse](https://github.com/seanmonstar/httparse) runtime structures but can also parse HTTP requests/responses captured to
text or to file.

## Example

```rust
use openapi::read_from_file;
use openapi_validator::{validate_raw_request, validate_raw_response, RootReplacement, ValidationSpec};

let spec = read_from_file("./data/petstore-3.1.0.yaml").unwrap();
let validation = ValidationSpec::new(spec, vec![RootReplacement {
   from: String::from("https://petstore3.swagger.io/api"),
   to: String::new()
}]).unwrap();

let r = validate_raw_request(&validation, "GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
assert!(r.is_ok(), "{}", r.unwrap_err());
let op = r.unwrap();
assert_eq!(
Some("Returns pet inventories by status".to_string()), op.summary);

let r = validate_raw_response(
    &validation,
    op,
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
 );
 assert!(r.is_ok(), "{}", r.unwrap_err());
 assert_eq!(Some("successful operation".to_string()), r.unwrap().0.description);
```
