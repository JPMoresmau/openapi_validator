use anyhow::{anyhow, Result};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::mem;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use walkdir::{DirEntry, WalkDir};

use crate::{
    validate_request, validate_response, RequestDefinition, ResponseDefinition, ValidationSpec,
};
use httparse::{Request, Status, EMPTY_HEADER};
use openapi::Operation;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestCase {
    id: String,
    request: String,
    api_operation: Option<String>,
    api_error: Option<String>,
    response: String,
    depends_on: Option<Vec<String>>,
}

impl TestCase {
    fn substitute<T: Fn(&str) -> Option<String>>(&self, substitutions: T) -> TestCase {
        let mut ret = self.clone();
        ret.request = substitute_str(&ret.request, &substitutions);
        ret.response = substitute_str(&ret.response, &substitutions);
        ret
    }
}

#[derive(Debug)]
enum ParseState {
    Text,
    FirstOpenCurly,
    Variable(String),
    FirstCloseCurly(String),
}

fn substitute_str<T: Fn(&str) -> Option<String>>(str: &str, substitutions: T) -> String {
    let mut st = ParseState::Text;
    let mut result = String::with_capacity(str.len());
    for c in str.chars() {
        st = match (c, st) {
            ('{', ParseState::Text) => ParseState::FirstOpenCurly,
            ('{', ParseState::FirstOpenCurly) => ParseState::Variable(String::new()),
            ('}', ParseState::Variable(v)) => ParseState::FirstCloseCurly(v),
            ('}', ParseState::FirstCloseCurly(v)) => {
                let real_v = v.trim();
                match substitutions(real_v) {
                    Some(repl) => result.push_str(&repl),
                    None => {
                        result.push_str("{{");
                        result.push_str(&v);
                        result.push_str("}}");
                    }
                }
                ParseState::Text
            }
            (c, ParseState::Variable(mut v)) => {
                v.push(c);
                ParseState::Variable(v)
            }
            (c, ParseState::Text) => {
                result.push(c);
                ParseState::Text
            }
            (c, ParseState::FirstOpenCurly) => {
                result.push('{');
                result.push(c);
                ParseState::Text
            }
            (c, st) => {
                println!("Unexpected char {c} in state {st:?} in {str}");
                result.push(c);
                st
            }
        }
    }
    result
}

#[derive(Debug)]
pub struct TestResult {
    pub id: String,
    pub result: Result<()>,
}

pub struct TestHarness {
    spec: ValidationSpec,
    client: Client,
    pub substitutions: Box<dyn Fn(&str) -> Option<String> + Sync + Send>,
}

#[derive(Clone, Debug)]
pub struct TestTree {
    cases: HashMap<String, TestCase>,
    //dependencies: Graph<String, ()>,
    children: HashMap<String, Vec<String>>,
    roots: Vec<String>,
}

impl TestTree {
    fn new(cases: Vec<TestCase>) -> Self {
        let mut cases_by_id = HashMap::new();
        let mut children = HashMap::new();
        let mut roots = Vec::new();
        //let mut dependencies = Graph::new();
        //let mut id_to_node = HashMap::new();
        for case in cases.into_iter() {
            //let ix = dependencies.add_node(case.id.clone());
            // id_to_node.insert(case.id.clone(),ix);
            cases_by_id.insert(case.id.clone(), case);
        }
        for case in cases_by_id.values() {
            if let Some(ds) = case.depends_on.as_ref() {
                if !ds.is_empty() {
                    /*if let Some(idx) = id_to_node.get(&case.id) {
                        for d in ds {
                            if let Some(didx) = id_to_node.get(d) {
                                dependencies.add_edge(*didx, *idx, ());
                            }
                        }
                    }*/
                    for d in ds {
                        let v = children.entry(d.clone()).or_insert_with(|| Vec::new());
                        v.push(case.id.clone());
                    }
                } else {
                    roots.push(case.id.clone());
                }
            } else {
                roots.push(case.id.clone());
            }
        }

        TestTree {
            cases: cases_by_id,
            children,
            roots,
        }
    }

    fn test_done(&mut self, id: &str) -> Vec<String> {
        let mut can_run = Vec::new();
        if let Some(children) = self.children.get(id) {
            for child in children {
                if let Some(case) = self.cases.get_mut(child) {
                    if let Some(ds) = case.depends_on.as_mut() {
                        ds.retain(|f| f != id);
                        if ds.is_empty() {
                            can_run.push(case.id.clone());
                        }
                    }
                }
            }
        }
        can_run
    }

    pub fn debug(&self) {
        let mut tree = self.clone();
        let mut ready = self.roots.clone();
        let mut todo = Vec::new();
        while !ready.is_empty() {
            for id in &ready {
                println!("{id}");
                let mut v = tree.test_done(id);
                todo.append(&mut v);
            }
            ready.clear();
            ready.append(&mut todo);
        }
    }
}

fn no_substitutions(_: &str) -> Option<String> {
    None
}

impl TestHarness {
    pub fn new(spec: ValidationSpec) -> TestHarness {
        TestHarness {
            spec,
            client: Client::new(),
            substitutions: Box::new(no_substitutions),
        }
    }
}

pub fn read_test_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<TestCase>> {
    from_file(path.as_ref(), |file| {
        serde_yaml::from_reader(file).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    })
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with("."))
        .unwrap_or(false)
}

fn is_yaml(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.ends_with(".yaml"))
        .unwrap_or(false)
}

pub fn read_tests_from_directory<P: AsRef<Path>>(path: P) -> io::Result<TestTree> {
    let mut all_tests = Vec::new();
    for entry in WalkDir::new(&path) {
        let entry = entry?;

        if !is_hidden(&entry) && is_yaml(&entry) {
            let mut v = read_test_from_file(entry.path())?;
            if let Some(diff) = pathdiff::diff_paths(entry.path(), &path) {
                if let Some(str) = diff.to_str() {
                    if let Some(ix) = str.rfind('/') {
                        let prefix = str[0..ix].replace('/', "::");
                        for test_case in v.iter_mut() {
                            test_case.id = format!("{prefix}::{}", test_case.id);
                        }
                    }
                }
            }

            all_tests.append(&mut v);
        }
    }

    let tree = TestTree::new(all_tests);
    //tree.debug();

    Ok(tree)
}

fn from_file<P>(path: &Path, parse: P) -> io::Result<Vec<TestCase>>
where
    P: FnOnce(BufReader<File>) -> io::Result<Vec<TestCase>>,
{
    let file = BufReader::new(File::open(path)?);
    parse(file)
}
/*
pub async fn run_tests<'a>(harness: &TestHarness<'a>, cases: &[TestCase]) -> Vec<TestResult> {
    let mut v = Vec::with_capacity(cases.len());
    for case in cases {
        let r = run_test_result(harness, case).await;
        v.push(r);
    }
    v
}*/

pub async fn run_tests_parallel(harness: TestHarness, mut tree: TestTree) -> Vec<TestResult> {
    let result = Vec::new();
    let harness = Arc::new(Mutex::new(harness));
    let results = Arc::new(Mutex::new(result));
    let ready = mem::replace(&mut tree.roots, Vec::new());
    let tree_tx = Arc::new(RwLock::new(tree));
    let mut handles = Vec::new();
    //let mut todo = Mutex::new(Vec::new());

    /*while !ready.is_empty() {
        ready.iter().map(|case| test_test_node(harness, case, &tree_tx, &results, &todo))
            .collect::<FuturesUnordered<_>>()
            .collect()
            .await;
        ready = todo.into_inner().unwrap();
        todo = Mutex::new(Vec::new());
    }*/
    for case in ready {
        let tree = tree_tx.clone();
        let results = results.clone();
        let harness = harness.clone();
        let handle =
            tokio::spawn(async move { run_test_node(&harness, case, &tree, &results).await });
        handles.push(handle);
    }
    for handle in handles {
        handle.await.unwrap();
    }
    Arc::try_unwrap(results).unwrap().into_inner()
}

use async_recursion::async_recursion;

#[async_recursion]
async fn run_test_node<'a>(
    harness: &Arc<Mutex<TestHarness>>,
    case: String,
    tree: &Arc<RwLock<TestTree>>,
    results_tx: &Arc<Mutex<Vec<TestResult>>>,
) {
    let c = {
        if let Some(case) = tree.read().await.cases.get(&case) {
            Some(case.clone())
        } else {
            None
        }
    };
    let r = {
        if let Some(case) = c {
            let harness = harness.clone();
            let id = case.id.clone();
            let r = run_test_result(&harness, &case).await;
            Some((r, id))
        } else {
            None
        }
    };
    if let Some((r, id)) = r {
        {
            results_tx.lock().await.push(r);
        }
        let can_run = {
            let mut t = tree.write().await;
            t.test_done(&id)
        };
        let mut handles = Vec::new();
        for child in can_run {
            let tree = tree.clone();
            let results = results_tx.clone();
            let harness = harness.clone();
            let handle =
                tokio::spawn(async move { run_test_node(&harness, child, &tree, &results).await });
            handles.push(handle);
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }
}
/*
pub async fn run_tests_parallel2<'a>(
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
*/
pub async fn run_test_result<'a>(harness: &Arc<Mutex<TestHarness>>, case: &TestCase) -> TestResult {
    let result = run_test(harness, case).await;
    if let Err(err) = &result {
        println!("{}: {err}", case.id);
    }
    TestResult {
        id: case.id.clone(),
        result,
    }
}

pub async fn run_test<'a>(harness: &Arc<Mutex<TestHarness>>, case: &TestCase) -> Result<()> {
    let harness = harness.lock().await;
    let case = case.substitute(&harness.substitutions);
    let req = parse_request(&harness, &case.request)?;
    match validate_request(&harness.spec, &req) {
        Ok(op) => {
            if let (Some(test_operation), Some(id)) = (&case.api_operation, &op.operation_id) {
                if test_operation != id {
                    return Err(anyhow!(
                        "wrong operation id, resolved {id}, test expected {test_operation}"
                    ));
                }
            }
            check_response(&harness, &case, req, op).await?;
            Ok(())
        }
        Err(err) if case.api_error == Some(err.to_string()) => Ok(()),
        Err(err) => Err(anyhow!("validate request failed: {err}")),
    }
}

async fn check_response(
    harness: &TestHarness,
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

            let (_, expected_value) = validate_response(&harness.spec, op, &raw_res)?;
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

fn parse_request<'a>(harness: &TestHarness, request: &'a str) -> Result<reqwest::Request> {
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

#[cfg(test)]
mod tests {
    use crate::test_runner::{no_substitutions, substitute_str};

    #[test]
    fn test_substitute() {
        assert_eq!(
            "hello".to_owned(),
            substitute_str("hello", no_substitutions)
        );
        assert_eq!(
            "{{hello}}".to_owned(),
            substitute_str("{{hello}}", no_substitutions)
        );
        assert_eq!(
            "{{ hello }}".to_owned(),
            substitute_str("{{ hello }}", no_substitutions)
        );
        assert_eq!(
            "a{{ hello }}b".to_owned(),
            substitute_str("a{{ hello }}b", no_substitutions)
        );
        assert_eq!("hello".to_owned(), substitute_str("hello", substitutions));
        assert_eq!(
            "world".to_owned(),
            substitute_str("{{hello}}", substitutions)
        );
        assert_eq!(
            "world".to_owned(),
            substitute_str("{{ hello }}", substitutions)
        );
        assert_eq!(
            "aworldb".to_owned(),
            substitute_str("a{{ hello }}b", substitutions)
        );
        assert_eq!(
            "aworldbworldc".to_owned(),
            substitute_str("a{{ hello }}b{{ hello }}c", substitutions)
        );
        assert_eq!(
            "aworldbvalc".to_owned(),
            substitute_str("a{{ hello }}b{{ var }}c", substitutions)
        );
        assert_eq!(
            "{\"tags\": []}".to_owned(),
            substitute_str("{\"tags\": []}", substitutions)
        );
    }

    fn substitutions(str: &str) -> Option<String> {
        match str {
            "hello" => Some("world".to_owned()),
            "var" => Some("val".to_owned()),
            _ => None,
        }
    }
}
