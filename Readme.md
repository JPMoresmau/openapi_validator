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

## Running full test cases

Another way to use this library is to run tests defined in YAML. You provide requests and responses in files, and the framework
will verify the request matches the spec, actually connect to the server and get the response, and verify the response matches both
the expected response and the spec. This can be use to test both an API server behavior and compliance with the spec.

The YAML files you use to define a test are as follows:

```yaml
- id: inventory_by_status
  request: |+
    GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1
    Host: petstore3.swagger.io

  api_operation: getInventory
  response: |+
    HTTP/1.1 200 OK
    content-type: application/json
    content-length: 2
    
    {}
```

It's possible to pass a substitution function to replace some tokens of the request and responses by values calculated at run time.

See [main.rs](src/main.rs) for a simple example.

## Root substitutions

It's possible to test a server that has a different root address than the one defined in the API (so the API can point to your production server
and you test locally for example) by providing a substitution map of the API defined root to the actual server root.
