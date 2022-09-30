use lazy_static::lazy_static;
use openapi::{read_from_file, Spec};
use openapi_validator::{
    validate_raw_request, validate_raw_response, RootReplacement, ValidationSpec,
};
use pretty_assertions::assert_eq;

lazy_static! {
    static ref PETSTORE_SPEC: Spec = read_from_file("./data/petstore-3.1.0.yaml").unwrap();
    static ref PETSTORE_VALIDATION: ValidationSpec<'static> = build_spec(vec![RootReplacement {
        from: String::from("https://petstore3.swagger.io/api"),
        to: String::new()
    }]);
}

fn build_spec<'a>(roots: Vec<RootReplacement>) -> ValidationSpec<'a> {
    ValidationSpec::new(&PETSTORE_SPEC, roots).unwrap()
}

#[test]
fn request_wrong_server() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v2/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_err());
    assert_eq!(
        "No server found for https://petstore3.swagger.io/api/v2/store/inventory",
        r.unwrap_err().to_string()
    );
}

#[test]
fn request_no_root() {
    let v_spec = build_spec(Vec::new());
    let r = validate_raw_request(&v_spec, "GET https://petstore3.swagger.io/api/v2/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_err());
    assert_eq!(
        "No server found for https://petstore3.swagger.io/api/v2/store/inventory".to_string(),
        r.unwrap_err().to_string()
    );
}

#[test]
fn request_wrong_path() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/store/inventory2 HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_err());
    assert_eq!(
        "no path found for /store/inventory2".to_string(),
        r.unwrap_err().to_string()
    );
}

#[test]
fn request_ok() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(
        Some("Returns pet inventories by status".to_string()),
        r.unwrap().summary
    );
}

#[test]
fn request_path_parameter_i64() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/pet/123 HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(Some("Find pet by ID".to_string()), r.unwrap().summary);
}

#[test]
fn request_path_parameter_i64_cannot_parse() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/pet/abc HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_err());
    assert_eq!(
        "cannot parse abc as i64: invalid digit found in string",
        r.unwrap_err().to_string()
    );
}

#[test]
fn request_path_parameter_string() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/user/PetOwner HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(
        Some("Get user by user name".to_string()),
        r.unwrap().summary
    );
}

#[test]
fn request_query_parameter_string() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/pet/findByStatus?status=sold HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(Some("Finds Pets by status".to_string()), r.unwrap().summary);
}

#[test]
fn request_query_parameter_string_wrong_value() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/pet/findByStatus?status=unknown HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_err());
    assert_eq!(
        "unknown not part of enum values",
        r.unwrap_err().to_string()
    );
}

#[test]
fn request_body_no_content_type() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "POST https://petstore3.swagger.io/api/v3/pet HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n{}");
    assert!(r.is_err());
    assert_eq!("no content type provided", r.unwrap_err().to_string());
}

#[test]
fn request_body_unknown_content_type() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "POST https://petstore3.swagger.io/api/v3/pet HTTP/1.1\r\nContent-Type: text/plain\r\nHOST: petstore3.swagger.io\r\n\r\n{}");
    assert!(r.is_err());
    assert_eq!(
        "no content for type text/plain",
        &r.unwrap_err().to_string()
    );
}

#[test]
fn request_body_json() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "POST https://petstore3.swagger.io/api/v3/pet HTTP/1.1\r\nHost: petstore3.swagger.io\r\nContent-Type: application/json\r\n\r\n{\"name\":\"Doggo\",\"photoUrls\":[]}");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(
        Some("Add a new pet to the store".to_string()),
        r.unwrap().summary
    );
}

#[test]
fn request_body_json_invalid() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "POST https://petstore3.swagger.io/api/v3/pet HTTP/1.1\r\nHost: petstore3.swagger.io\r\nContent-Type: application/json\r\n\r\n{\"name\":\"Doggo\"}");
    assert!(r.is_err());
    assert_eq!(
        "\"photoUrls\" is a required property",
        r.unwrap_err().to_string()
    );
}

#[test]
fn request_header() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "DELETE https://petstore3.swagger.io/api/v3/pet/123 HTTP/1.1\r\nHost: petstore3.swagger.io\r\nContent-Type: application/json\r\napi_key: abc\r\n\r\n{\"name\":\"Doggo\"}");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(Some("Deletes a pet".to_string()), r.unwrap().summary);
}

#[test]
fn response_wrong_status() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    let op = r.unwrap();
    assert_eq!(
        Some("Returns pet inventories by status".to_string()),
        op.summary
    );

    let r = validate_raw_response(&PETSTORE_VALIDATION, &op, "HTTP/1.1 201 No Content\r\n\r\n");
    assert!(r.is_err());
    assert_eq!("no matching response", r.unwrap_err().to_string());
}

#[test]
fn response_content_ok() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    let op = r.unwrap();
    assert_eq!(
        Some("Returns pet inventories by status".to_string()),
        op.summary
    );

    let r = validate_raw_response(
        &PETSTORE_VALIDATION,
        &op,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert!(r.is_ok(), "{}", r.unwrap_err());
    assert_eq!(
        Some("successful operation".to_string()),
        r.unwrap().0.description
    );
}

#[test]
fn response_content_invalid() {
    let r = validate_raw_request(&PETSTORE_VALIDATION, "GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
    assert!(r.is_ok(), "{}", r.unwrap_err());
    let op = r.unwrap();
    assert_eq!(
        Some("Returns pet inventories by status".to_string()),
        op.summary
    );

    let r = validate_raw_response(
        &PETSTORE_VALIDATION,
        &op,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\naa",
    );
    assert!(r.is_err());
    assert_eq!(
        "cannot parse input expected value at line 1 column 1",
        r.unwrap_err().to_string()
    );
}
