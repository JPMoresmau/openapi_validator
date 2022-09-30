use anyhow::{anyhow, Result};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use crate::{
    validate_request, validate_response, RequestDefinition, ResponseDefinition, ValidationSpec,
};
use httparse::{Request, Status, EMPTY_HEADER};
use openapi::Operation;

#[derive(Debug, Serialize, Deserialize)]
pub struct TestCase {
    id: String,
    request: String,
    api_operation: Option<String>,
    api_error: Option<String>,
    response: String,
}

pub struct TestResult {
    pub id: String,
    pub result: Result<()>,
}

pub struct TestHarness<'a> {
    spec: &'a ValidationSpec<'a>,
    client: Client,
}

impl<'a> TestHarness<'a> {
    pub fn new(spec: &'a ValidationSpec<'a>) -> TestHarness<'a> {
        TestHarness {
            spec,
            client: Client::new(),
        }
    }
}

pub fn read_test_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<TestCase>> {
    from_file(path.as_ref(), |file| {
        serde_yaml::from_reader(file).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    })
}

fn from_file<P>(path: &Path, parse: P) -> io::Result<Vec<TestCase>>
where
    P: FnOnce(BufReader<File>) -> io::Result<Vec<TestCase>>,
{
    let file = BufReader::new(File::open(path)?);
    parse(file)
}

pub async fn run_tests<'a>(harness: &TestHarness<'a>, cases: &[TestCase]) -> Vec<TestResult> {
    let mut v = Vec::with_capacity(cases.len());
    for case in cases {
        let r = run_test_result(harness, case).await;
        v.push(r);
    }
    v
}

pub async fn run_tests_parallel<'a>(
    harness: &TestHarness<'a>,
    cases: &[TestCase],
) -> Vec<TestResult> {
    cases
        .iter()
        .map(|case| run_test_result(harness, case))
        .collect::<FuturesUnordered<_>>()
        .collect()
        .await
}

pub async fn run_test_result<'a>(harness: &TestHarness<'a>, case: &TestCase) -> TestResult {
    let result = run_test(harness, case).await;
    if let Err(err) = &result {
        println!("{}: {err}", case.id);
    }
    TestResult {
        id: case.id.clone(),
        result,
    }
}

pub async fn run_test<'a>(harness: &TestHarness<'a>, case: &TestCase) -> Result<()> {
    let req = parse_request(harness, &case.request)?;
    match validate_request(harness.spec, &req) {
        Ok(op) => {
            if let (Some(test_operation), Some(id)) = (&case.api_operation, &op.operation_id) {
                if test_operation != id {
                    return Err(anyhow!(
                        "wrong operation id, resolved {id}, test expected {test_operation}"
                    ));
                }
            }
            check_response(harness, case, req, op).await?;
            Ok(())
        }
        Err(err) if case.api_error == Some(err.to_string()) => Ok(()),
        Err(err) => Err(anyhow!("validate request failed: {err}")),
    }
}

async fn check_response<'a>(
    harness: &TestHarness<'a>,
    case: &TestCase,
    request: reqwest::Request,
    op: &Operation,
) -> Result<()> {
    let response = harness.client.execute(request).await?;

    let mut headers = [EMPTY_HEADER; 16];
    let mut req = httparse::Response::new(&mut headers);
    let expected_bytes = case.response.as_bytes();
    let res = req.parse(expected_bytes)?;
    match res {
        Status::Partial => {
            return Err(anyhow!("partial response provided in text"));
        }
        Status::Complete(sz) => {
            let raw_res = (req, case.response.as_str(), sz);

            let (_, expected_value) = validate_response(harness.spec, op, &raw_res)?;
            if let Some(status) = raw_res.status() {
                if response.status().as_u16() != status {
                    return Err(anyhow!(
                        "unexpected status code, expected {status}, received {}",
                        response.status()
                    ));
                }
            }
            for h in raw_res.0.headers.iter() {
                let v = response.headers().get(h.name);
                let expected = std::str::from_utf8(h.value)?;
                match v {
                    Some(v) => match v.to_str() {
                        Ok(v) => {
                            if v != expected {
                                return Err(anyhow!(
                                    "unexpected value for header {}, expected {}, received {v}",
                                    h.name,
                                    expected
                                ));
                            }
                        }
                        Err(err) => return Err(err.into()),
                    },
                    None => {
                        return Err(anyhow!("missing header {}", h.name));
                    }
                }
            }

            if let Some(expected_value) = expected_value {
                let received_bytes = response.bytes().await?;
                let received_content: Value =
                    serde_json::from_str(std::str::from_utf8(&received_bytes)?)?;
                if received_content != expected_value {
                    return Err(anyhow!(
                        "unexpected content expected `{}`, received `{}`",
                        expected_value,
                        received_content,
                    ));
                }
            }
        }
    }

    Ok(())
}

fn parse_request<'a>(harness: &TestHarness<'a>, request: &'a str) -> Result<reqwest::Request> {
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    let res = req
        .parse(request.as_bytes())
        .map_err(|err| anyhow!("cannot parse request: {err}"))?;
    match res {
        Status::Partial => Err(anyhow!("partial request")),
        Status::Complete(sz) => {
            let raw_req = (req, request, sz);
            /*let b= match (raw_req.method(), raw_req.path()){
                (Some("GET"),Some(path)) => harness.client.get(path),
                (method,_) => return Err(anyhow!("unknown request {method:?}"))
            };*/
            let mut b = match (raw_req.method(), raw_req.path()) {
                (Some(m), Some(path)) => match Method::from_bytes(m.as_bytes()) {
                    Ok(m) => harness.client.request(m, path),
                    Err(err) => return Err(anyhow!("unknown method {err}")),
                },
                (method, _) => return Err(anyhow!("unknown request {method:?}")),
            };
            for h in raw_req.0.headers.iter() {
                b = b.header(h.name, h.value);
            }
            match raw_req.body() {
                Ok(Some(body)) => b = b.json(body),
                Ok(None) => {}
                Err(err) => return Err(err),
            }

            b.build()
                .map_err(|err| anyhow!("Cannot build request: {err}"))
        }
    }
}
