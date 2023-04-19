//! Validates requests and responses against an OpenAPI spec.
//!
//! # Examples
//!
//! ```
//! use openapi::read_from_file;
//! use openapi_validator::{validate_raw_request, validate_raw_response, RootReplacement, ValidationSpec};
//!
//! let spec = read_from_file("./data/petstore-3.1.0.yaml").unwrap();
//! let validation = ValidationSpec::new(spec, vec![RootReplacement {
//!     from: String::from("https://petstore3.swagger.io/api"),
//!     to: String::new()
//! }]).unwrap();
//!
//! let r = validate_raw_request(&validation, "GET https://petstore3.swagger.io/api/v3/store/inventory HTTP/1.1\r\nHOST: petstore3.swagger.io\r\n\r\n");
//! assert!(r.is_ok(), "{}", r.unwrap_err());
//! let op = r.unwrap();
//! assert_eq!(
//! Some("Returns pet inventories by status".to_string()), op.summary);
//!
//! let r = validate_raw_response(
//!     &validation,
//!     op,
//!     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
//!  );
//!  assert!(r.is_ok(), "{}", r.unwrap_err());
//!  assert_eq!(Some("successful operation".to_string()), r.unwrap().0.description);
//! ```
use std::fs::File;
use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use httparse::{Request, Status, EMPTY_HEADER};
use jsonschema::{JSONSchema, SchemaResolver, SchemaResolverError};
use openapi::{
    Format, FormatOrString, Header, Operation, Parameter, ParameterLocation, PathItem, Reference,
    RequestBody, Response, Schema, Server, Spec, Type,
};
use querystring::querify;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufReader};
use std::path::Path;
use url::Url;

/// OpenAPI Spec and validation information.
#[derive(Debug, Clone)]
pub struct ValidationSpec {
    /// The parsed OpenAPI spec.
    spec: Spec,
    /// The raw Value representing the spec.
    raw_spec: Arc<Value>,
    /// The root URLs replacements.
    pub roots: Vec<RootReplacement>,
}

/// Root replacement, to validate requests going to a different
/// server root than what specified in the spec.
///
/// This allows for example to have a spec referencing your production
/// server but validate calls going to a test server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootReplacement {
    /// Root URL for the actual requests.
    pub from: String,
    /// Destination root, as defined in the spec.
    pub to: String,
}

/// Read the root replacements from a YAML file, containing a list of objects
/// with `from` and `to` fields.
pub fn read_replacements_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<RootReplacement>> {
    let file = BufReader::new(File::open(path)?);
    serde_yaml::from_reader(file).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

impl ValidationSpec {
    /// Create a new Validation Spec from a parsed spec, with the given replacement for root URLs.
    pub fn new(spec: Spec, roots: Vec<RootReplacement>) -> Result<ValidationSpec> {
        let raw_spec = Arc::new(
            serde_json::to_value(&spec).map_err(|e| anyhow!("cannot get spec as value: {e}"))?,
        );
        Ok(ValidationSpec {
            spec,
            raw_spec,
            roots,
        })
    }
}

/// Validate a raw HTTP request against the OpenAPI.
/// The request is passed as a `&str` and will be parsed.
/// Returns the OpenAPI Operation the request is for, or an error.
pub fn validate_raw_request<'a, 'b>(
    spec: &'a ValidationSpec,
    request: &'b str,
) -> Result<&'a Operation>
where
    'a: 'b,
{
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    let res = req.parse(request.as_bytes())?;
    match res {
        Status::Partial => Err(anyhow!("partial request")),
        Status::Complete(sz) => validate_request(spec, &(req, request, sz)),
    }
}

/// Validate a HTTP request against the OpenAPI.
/// Returns the OpenAPI Operation the request is for, or an error.
pub fn validate_request<'a, 'b, T>(
    spec: &'a ValidationSpec,
    request: &'b T,
) -> Result<&'a Operation>
where
    T: RequestDefinition,
{
    let (_server, path) = match request.path() {
        Some(path) => validate_uri(&spec.spec, path, &spec.roots)?,
        None => return Err(anyhow!("no path in request")),
    };
    let o_query = path.split_once('?');

    let path = o_query.map(|(a, _)| a).unwrap_or(path);

    let (path, o_values) = find_path(&spec.spec, path)?;
    let op = match request.method() {
        Some("GET") => path.get.as_ref(),
        Some("POST") => path.post.as_ref(),
        Some("PUT") => path.put.as_ref(),
        Some("PATCH") => path.patch.as_ref(),
        Some("DELETE") => path.delete.as_ref(),
        Some("OPTIONS") => path.options.as_ref(),
        Some(other) => return Err(anyhow!("unsupported method: {other}")),
        None => return Err(anyhow!("no method found")),
    }
    .ok_or_else(|| anyhow!("No method matching {}", request.method().unwrap()))?;

    let query_values: Option<HashMap<&'b str, &'b str>> =
        o_query.map(|(_, b)| HashMap::from_iter(querify(b).into_iter()));

    if let Some(values) = o_values {
        for (key, value) in values.iter() {
            let param = find_parameter(&spec.spec, path, op, key, ParameterLocation::Path)?;
            if let Some(schema) = &param.schema {
                validate_value(schema, value)?;
            }
        }
    }

    if let Some(values) = query_values {
        for (key, value) in values.iter() {
            let param = find_parameter(&spec.spec, path, op, key, ParameterLocation::Query)?;
            if let Some(schema) = &param.schema {
                validate_value(schema, value)?;
            }
        }
    }

    validate_request_headers(&spec.spec, path, op, request)?;

    if let Some(body_ref) = &op.request_body {
        let body = resolve_ref_request_body(&spec.spec, body_ref)?;
        let content_type = request
            .header("content-type")?
            .ok_or_else(|| anyhow!("no content type provided"))?;
        let content_type = if let Some((p, _)) = content_type.split_once(';') {
            p
        } else {
            content_type
        };
        match body.content.get(content_type) {
            Some(mt) => {
                if let Some(schema) = &mt.schema {
                    if let Some(body) = request.body()? {
                        validate_body(spec.raw_spec.clone(), schema, body, false)?;
                    // streamed by reqwest and not available
                    } else if content_type != "multipart/form-data" {
                        return Err(anyhow!("no body in request"));
                    }
                }
            }
            None => return Err(anyhow!("no content for type {content_type}")),
        }
    }
    Ok(op)
}

/// Validates a raw response given the Operation that returned it.
/// The response is passed as a `&str` and will be parsed.
pub fn validate_raw_response<'a>(
    spec: &'a ValidationSpec,
    op: &'a Operation,
    response: &str,
) -> Result<(&'a Reference<Response>, Option<Value>)> {
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = httparse::Response::new(&mut headers);
    let res = req.parse(response.as_bytes())?;
    match res {
        Status::Partial => Err(anyhow!("partial request")),
        Status::Complete(sz) => validate_response(spec, op, &(req, response, sz)),
    }
}

/// Validates a response given the Operation that returned it.
pub fn validate_response<'a, T>(
    spec: &'a ValidationSpec,
    op: &'a Operation,
    response: &T,
) -> Result<(&'a Reference<Response>, Option<Value>)>
where
    T: ResponseDefinition,
{
    if let Some(status) = response.status() {
        if let Some(resps) = &op.responses {
            for (id, resp) in &resps.response {
                if &status.to_string() == id {
                    // No content
                    if status == 204 || status == 304 {
                        return Ok((resp, None));
                    }
                    return check_response(spec, resp, response);
                }
            }
            if let Some(resp) = &resps.default {
                return check_response(spec, resp, response);
            }
        }

        return Err(anyhow!("no matching response"));
    }
    Err(anyhow!("no status in response"))
}

/// Check the response matches what's expected by the OpenAPI response.
fn check_response<'a, T>(
    spec: &'a ValidationSpec,
    ref_response: &'a Reference<Response>,
    response: &T,
) -> Result<(&'a Reference<Response>, Option<Value>)>
where
    T: ResponseDefinition,
{
    let r = resolve_ref_response(&spec.spec, ref_response)?;
    validate_response_headers(&spec.spec, r, response)?;
    let content_type = response
        .header("content-type")?
        .ok_or_else(|| anyhow!("no content type provided"))?;
    let value = match r.content.get(content_type) {
        Some(mt) => {
            if let Some(schema) = &mt.schema {
                if let Some(body) = response.body()? {
                    Some(validate_body(spec.raw_spec.clone(), schema, body, true)?)
                } else {
                    return Err(anyhow!("no body in response"));
                }
            } else {
                None
            }
        }
        None => return Err(anyhow!("no response content for type {content_type}")),
    };
    Ok((ref_response, value))
}

/// Abstraction over a HTTP Request.
pub trait RequestDefinition {
    /// The HTTP method.
    fn method(&self) -> Option<&str>;

    /// The request path.
    fn path(&self) -> Option<&str>;

    /// Get the request header value for the given header name.
    fn header(&self, key: &str) -> Result<Option<&str>>;

    /// Get the body.
    fn body(&self) -> Result<Option<&str>>;
}

/// Abstraction over a HTTP response.
pub trait ResponseDefinition {
    /// HTTP response status.
    fn status(&self) -> Option<u16>;

    /// Get the response header value for the given header name.
    fn header(&self, key: &str) -> Result<Option<&str>>;

    /// Get the response body.
    fn body(&self) -> Result<Option<&str>>;
}

impl<'a, 'b> RequestDefinition for (Request<'a, 'b>, &str, usize) {
    fn method(&self) -> Option<&str> {
        self.0.method
    }

    fn path(&self) -> Option<&str> {
        self.0.path
    }

    fn header(&self, key: &str) -> Result<Option<&str>> {
        let o_v = self.0.headers.iter().find_map(|h| {
            if h.name.to_ascii_lowercase() == key.to_ascii_lowercase() {
                Some(h.value)
            } else {
                None
            }
        });
        match o_v {
            Some(v) => std::str::from_utf8(v).map(Option::Some).map_err(Into::into),
            None => Ok(None),
        }
    }

    fn body(&self) -> Result<Option<&str>> {
        if self.2 > 0 {
            Ok(Some(&self.1[self.2..]))
        } else {
            Ok(None)
        }
    }
}

impl<'a, 'b> ResponseDefinition for (httparse::Response<'a, 'b>, &str, usize) {
    fn status(&self) -> Option<u16> {
        self.0.code
    }

    fn header(&self, key: &str) -> Result<Option<&str>> {
        let o_v = self.0.headers.iter().find_map(|h| {
            if h.name.to_ascii_lowercase() == key.to_ascii_lowercase() {
                Some(h.value)
            } else {
                None
            }
        });
        match o_v {
            Some(v) => std::str::from_utf8(v).map(Option::Some).map_err(Into::into),
            None => Ok(None),
        }
    }

    fn body(&self) -> Result<Option<&str>> {
        if self.2 > 0 {
            Ok(Some(&self.1[self.2..]))
        } else {
            Ok(None)
        }
    }
}

impl RequestDefinition for reqwest::Request {
    fn method(&self) -> Option<&str> {
        Some(self.method().as_str())
    }

    fn path(&self) -> Option<&str> {
        Some(self.url().as_str())
    }

    fn header(&self, key: &str) -> Result<Option<&str>> {
        match self.headers().get(key) {
            Some(v) => v.to_str().map(Option::Some).map_err(Into::into),
            None => Ok(None),
        }
    }

    fn body(&self) -> Result<Option<&str>> {
        self.body()
            .and_then(|b| b.as_bytes())
            .map(std::str::from_utf8)
            .map_or(Ok(None), |v| v.map(Some).map_err(Into::into))
    }
}

/*
impl ResponseDefinition for reqwest::Response {
    fn status(&self) -> Option<u16> {
        Some(self.status().as_u16())
    }

    fn header(&self, key: &str) -> Result<Option<&str>> {
        match self.headers().get(key) {
            Some(v) => v.to_str().map(Option::Some).map_err(Into::into),
            None => Ok(None),
        }
    }

    fn body(&self) -> Result<Option<&str>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {self.text().await}).map(|s| Some(s.as_str())).map_err(Into::into)
    }
}
*/

/// Find a parameter in the given path and operation.
fn find_parameter<'a>(
    spec: &'a Spec,
    path: &'a PathItem,
    op: &'a Operation,
    key: &str,
    loc: ParameterLocation,
) -> Result<&'a Parameter> {
    path.parameters
        .iter()
        .chain(op.parameters.iter())
        .find_map(|r| match resolve_ref_parameter(spec, r) {
            Ok(param) if param.r#in == loc && param.name == key => Some(param),
            Ok(_p) => None,
            Err(err) => {
                eprintln!("{err}");
                None
            }
        })
        .ok_or_else(|| anyhow!("Parameter {key} not found"))
}

/// Validate the request headers.
fn validate_request_headers<'a, T>(
    spec: &'a Spec,
    path: &'a PathItem,
    op: &'a Operation,
    req: &T,
) -> Result<()>
where
    T: RequestDefinition,
{
    for r in path.parameters.iter().chain(op.parameters.iter()) {
        match resolve_ref_parameter(spec, r) {
            Ok(param) if param.r#in == ParameterLocation::Header => {
                match req.header(&param.name)? {
                    Some(v) => {
                        if let Some(schema) = &param.schema {
                            //eprintln!("header value: {v}");
                            validate_value(schema, v)?;
                        }
                    }
                    None => {
                        if param.required {
                            return Err(anyhow!("header {} not found", param.name));
                        }
                    }
                }
            }
            Ok(_p) => {}
            Err(err) => {
                eprintln!("{err}");
            }
        }
    }
    Ok(())
}

fn validate_response_headers<'a, T>(spec: &'a Spec, r: &'a Response, res: &T) -> Result<()>
where
    T: ResponseDefinition,
{
    for (name, h) in &r.headers {
        match resolve_ref_header(spec, h) {
            Ok(header) => {
                match res.header(name)? {
                    Some(v) => {
                        if let Some(schema) = &header.schema {
                            //eprintln!("header value: {v}");
                            validate_value(schema, v)?;
                        }
                    }
                    None => {
                        if header.required {
                            return Err(anyhow!("header {} not found", name));
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("{err}");
            }
        }
    }
    Ok(())
}

/// Resolve a reference to a URL parameter.
fn resolve_ref_parameter<'a>(
    spec: &'a Spec,
    reference: &'a Reference<Parameter>,
) -> Result<&'a Parameter> {
    match &reference.object {
        Some(o) => Ok(o),
        None => match &reference.r#ref {
            Some(r) => {
                if let Some(n) = r.strip_prefix("#/components/parameters/") {
                    spec.components
                        .parameters
                        .get(n)
                        .and_then(|p| p.object.as_ref())
                        .ok_or_else(|| anyhow!("parameter {n} not found"))
                } else {
                    Err(anyhow!("reference {r} not handled"))
                }
            }
            None => Err(anyhow!("No reference, no object")),
        },
    }
}

/// Resolve a reference to a request body.
fn resolve_ref_request_body<'a>(
    spec: &'a Spec,
    reference: &'a Reference<RequestBody>,
) -> Result<&'a RequestBody> {
    match &reference.object {
        Some(o) => Ok(o),
        None => match &reference.r#ref {
            Some(r) => {
                if let Some(n) = r.strip_prefix("#/components/requestBodies/") {
                    spec.components
                        .request_bodies
                        .get(n)
                        .and_then(|p| p.object.as_ref())
                        .ok_or_else(|| anyhow!("request body {n} not found"))
                } else {
                    Err(anyhow!("request body reference {r} not handled"))
                }
            }
            None => Err(anyhow!("No reference, no object")),
        },
    }
}

/// Resolve a reference to a response.
pub fn resolve_ref_response<'a>(
    spec: &'a Spec,
    reference: &'a Reference<Response>,
) -> Result<&'a Response> {
    match &reference.r#ref {
        Some(r) => {
            if let Some(n) = r.strip_prefix("#/components/responses/") {
                spec.components
                    .responses
                    .get(n)
                    .and_then(|p| p.object.as_ref())
                    .ok_or_else(|| anyhow!("response {n} not found"))
            } else {
                Err(anyhow!("response reference {r} not handled"))
            }
        }
        None => match &reference.object {
            Some(o) => Ok(o),
            None => Err(anyhow!("No reference, no object for response")),
        },
    }
}

/// Resolve a reference to a header.
fn resolve_ref_header<'a>(spec: &'a Spec, reference: &'a Reference<Header>) -> Result<&'a Header> {
    match &reference.object {
        Some(o) => Ok(o),
        None => match &reference.r#ref {
            Some(r) => {
                if let Some(n) = r.strip_prefix("#/components/headers/") {
                    spec.components
                        .headers
                        .get(n)
                        .and_then(|p| p.object.as_ref())
                        .ok_or_else(|| anyhow!("response {n} not found"))
                } else {
                    Err(anyhow!("header reference {r} not handled"))
                }
            }
            None => Err(anyhow!("No reference, no object for header")),
        },
    }
}

/// JSON Schema resolver for the given spec.
struct SpecResolver {
    /// The raw spec value.
    spec: Arc<Value>,
    /// Are we validating a response (true) or a request (false).
    is_response: bool,
}

impl SchemaResolver for SpecResolver {
    fn resolve(
        &self,
        _root_schema: &Value,
        url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        // Resolve local types in the given Spec.
        if let Some(path) = url.to_string().strip_prefix("json-schema://spec") {
            let v = self
                .spec
                .pointer(path)
                .ok_or_else(|| anyhow!("path '{path}' cannot be resolved"))?;
            let mut v = serde_json::from_str(&v.to_string().replace("#/", "json-schema://spec/"))
                .map_err(|e| anyhow!("cannot parse transformed schema {e}"))?;
            post_process_schema(
                &mut v,
                if self.is_response {
                    "writeOnly"
                } else {
                    "readOnly"
                },
            );
            return Ok(Arc::new(v));
        }
        Err(anyhow!("cannot resolve {url}"))
    }
}

/// The JSON Schema implementation does not handle readOnly/writeOnly, so we do it ourselves.
/// Remove from the required list the properties marked with the given flag.
fn post_process_schema(value: &mut Value, flag_to_ignore: &str) {
    if let Some(props) = value.get("properties").and_then(Value::as_object) {
        let properties_to_ignore: Vec<String> = props
            .iter()
            .filter(|(_, p)| p.get(flag_to_ignore) == Some(&Value::Bool(true)))
            .map(|(k, _)| k.clone())
            .collect();
        if let Some(required) = value.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(
                |v| matches!(v.as_str(), Some(s) if !properties_to_ignore.iter().any(|v| v==s)),
            );
        }
    }
}

/// Validate a given request or response body against the JSON Schema.
fn validate_body(
    v_spec: Arc<Value>,
    schema: &Schema,
    value: &str,
    is_response: bool,
) -> Result<Value> {
    let v = serde_json::to_value(schema).map_err(|e| anyhow!("cannot get schema as value: {e}"))?;
    // Replace local paths by a marker, this will be processed by the resolver.
    let v = serde_json::from_str(&v.to_string().replace("#/", "json-schema://spec/"))
        .map_err(|e| anyhow!("cannot parse transformed schema {e}"))?;

    let mut opts = JSONSchema::options();

    opts.with_resolver(SpecResolver {
        spec: v_spec,
        is_response,
    });

    let compiled = opts
        .compile(&v)
        .map_err(|e| anyhow!("cannot compile schema: {e}"))?;

    let input = serde_json::from_str(value).map_err(|e| anyhow!("cannot parse input {e}"))?;
    let r = match compiled.validate(&input) {
        Ok(_) => Ok(()),
        Err(it) => Err(anyhow!(it
            .map(|e| e.to_string())
            .collect::<Vec<String>>()
            .join("\n"))),
    };
    r.map(|_| input)
}

/// Validate that a given simple value conforms to the given schema.
fn validate_value(schema: &Schema, value: &str) -> Result<()> {
    if !schema.r#enum.is_empty() && !schema.r#enum.iter().any(|e| e == value) {
        return Err(anyhow!("{value} not part of enum values"));
    }
    for tp in &schema.r#type {
        match tp {
            Type::Integer => {
                if let Some(fmt) = &schema.format {
                    match fmt {
                        FormatOrString::Format(Format::Int32) => {
                            value
                                .parse::<i32>()
                                .map_err(|e| anyhow!("cannot parse {value} as i32: {e}"))?;
                        }
                        FormatOrString::Format(Format::Int64) => {
                            value
                                .parse::<i64>()
                                .map_err(|e| anyhow!("cannot parse {value} as i64: {e}"))?;
                        }
                        fmt => return Err(anyhow!("unhandled format {fmt:?}")),
                    }
                }
            }
            Type::String => {}
            Type::Boolean => {
                if value != "true" && value != "false" {
                    return Err(anyhow!("not a boolean: {value}"));
                }
            }
            tp => return Err(anyhow!("unhandled type {tp:?}")),
        }
    }
    Ok(())
}

/// Validate a request URI matches a given server in the spec, using the root replacements provided.
fn validate_uri<'a, 'b>(
    spec: &'a Spec,
    url: &'b str,
    roots: &[RootReplacement],
) -> Result<(&'a Server, &'b str)> {
    for replacement in roots {
        if let Some(suffix) = url.strip_prefix(&replacement.from) {
            for server in spec.servers.iter() {
                if let Some(server_suffix) = server.url.strip_prefix(&replacement.to) {
                    if let Some(path) = suffix.strip_prefix(server_suffix) {
                        return Ok((server, path));
                    }
                }
            }
        }
    }
    for server in spec.servers.iter() {
        if let Some(path) = url.strip_prefix(&server.url) {
            return Ok((server, path));
        }
    }
    Err(anyhow!("No server found for {url}"))
}

/// find the path item a given request matches.
fn find_path<'a, 'b>(
    spec: &'a Spec,
    path: &'b str,
) -> Result<(&'a PathItem, Option<HashMap<&'a str, &'b str>>)> {
    // Exact match.
    for (pattern, item) in spec.paths.iter() {
        if pattern == path {
            return Ok((item, None));
        }
    }
    // Match with parameter. Take the match with the least substitutions.
    let mut matching = vec![];
    let mut sz = usize::MAX;
    for (pattern, item) in spec.paths.iter() {
        if pattern.contains('{') {
            if let Some(values) = match_path_pattern(pattern, path) {
                sz = sz.min(values.len());
                matching.push((item, Some(values)));
            }
        }
    }
    for (item, mvalues) in matching.into_iter() {
        if let Some(values) = mvalues {
            if values.len() == sz {
                return Ok((item, Some(values)));
            }
        }
    }

    Err(anyhow!("no path found for {path}"))
}

/// Match a path with the given pattern, and returns the map of parameter names to values
/// if there's a match.
fn match_path_pattern<'a, 'b>(
    pattern: &'a str,
    path: &'b str,
) -> Option<HashMap<&'a str, &'b str>> {
    let ps = extract_parameters(pattern);
    let mut m = HashMap::new();
    let mut pat_offset = 0;
    let mut offset = 0;
    for (start, name) in ps.iter() {
        let pat_start = start - pat_offset + offset;
        if pat_start > path.len() {
            return None;
        }
        if path[offset..pat_start] != pattern[pat_offset..*start] {
            return None;
        }
        pat_offset = start + name.len() + 2;
        match path[pat_start..].find('/') {
            Some(ix) => {
                m.insert(*name, &path[pat_start..ix + pat_start]);
                offset = ix + pat_start;
            }
            None => {
                m.insert(*name, &path[pat_start..]);
                offset = path.len();
            }
        }
    }
    if path[offset.min(path.len())..] != pattern[pat_offset.min(pattern.len())..] {
        return None;
    }
    Some(m)
}

/// Extract parameters from a path.
fn extract_parameters(path: &str) -> Vec<(usize, &str)> {
    let mut start = 0;
    let mut ret = vec![];
    for (ix, c) in path.chars().enumerate() {
        if c == '{' {
            start = ix;
        } else if c == '}' {
            ret.push((start, &path[start + 1..ix]))
        }
    }
    ret
}

#[test]
fn test_extract_parameters() {
    assert!(extract_parameters("/pet").is_empty());
    pretty_assertions::assert_eq!(vec![(5, "petId")], extract_parameters("/pet/{petId}"));
    pretty_assertions::assert_eq!(vec![(5, "petId")], extract_parameters("/pet/{petId}"));
    pretty_assertions::assert_eq!(
        vec![(5, "petId"), (18, "partId")],
        extract_parameters("/pet/{petId}/part/{partId}")
    );
    pretty_assertions::assert_eq!(
        vec![(10, "owner-name"), (23, "pet-name")],
        extract_parameters("pet/owner/{owner-name}/{pet-name}/feed")
    );
}

#[test]
fn test_match_path_pattern() {
    assert!(match_path_pattern("/pet/{petId}/more", "/pet/123").is_none());
    assert!(match_path_pattern("/pet/{petId}", "/pet/123/more").is_none());
    assert!(match_path_pattern("/pet/{petId}/{petPart}", "/pet/123").is_none());

    let m = match_path_pattern("/pet/{petId}", "/pet/123").unwrap();
    pretty_assertions::assert_eq!(1, m.len());
    pretty_assertions::assert_eq!(Some(&"123"), m.get("petId"));
    let m = match_path_pattern("/pet/{petId}/part", "/pet/123/part").unwrap();
    pretty_assertions::assert_eq!(1, m.len());
    pretty_assertions::assert_eq!(Some(&"123"), m.get("petId"));
    let m = match_path_pattern("/pet/{petId}/part/{partId}", "/pet/123/part/345").unwrap();
    pretty_assertions::assert_eq!(2, m.len());
    pretty_assertions::assert_eq!(Some(&"123"), m.get("petId"));
    pretty_assertions::assert_eq!(Some(&"345"), m.get("partId"));
    let m = match_path_pattern(
        "/pet/owner/{owner-name}/{pet-name}/feed",
        "/pet/owner/jon/garfield/feed",
    )
    .unwrap();
    pretty_assertions::assert_eq!(2, m.len());
    pretty_assertions::assert_eq!(Some(&"jon"), m.get("owner-name"));
    pretty_assertions::assert_eq!(Some(&"garfield"), m.get("pet-name"));
}
