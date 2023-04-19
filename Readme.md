# Open API validator

Given an OpenAPI 3.1 specification, verifies that HTTP requests and responses actually sent and received from a server match the spec.

For example, you can integrate the validator when testing your API to ensure that not only the API returns what you expect, but that the
requests your tests send and the responses they get conform to the spec.

Integrates with Rust [httparse](https://github.com/seanmonstar/httparse) runtime structures but can also parse HTTP requests/responses captured to 
text or to file. 
