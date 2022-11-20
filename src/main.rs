use openapi::read_from_file;
use openapi_validator::{
    read_replacements_from_file, read_tests_from_directory, run_tests_parallel, TestHarness,
    ValidationSpec,
};
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: openapi_validator <spec file name> <replacements> <test cases directory>");
        process::exit(1);
    }
    match read_from_file(&args[1]) {
        Ok(spec) => {
            println!("Spec OK");
            match read_replacements_from_file(&args[2]) {
                Ok(reps) => match ValidationSpec::new(spec, reps) {
                    Ok(v_spec) => match read_tests_from_directory(&args[3]) {
                        Ok(cases) => {
                            let mut harness = TestHarness::new(v_spec);
                            harness.substitutions =  Box::new(|name:&str| {
                                    Some(name.to_owned())
                                }
                            );
                            let v = run_tests_parallel(harness, cases).await;
                            let total = v.len();
                            let success = v.iter().filter(|r| r.result.is_ok()).count();
                            println!("{success}/{total} passed, {} failed", total - success);
                        }
                        Err(err) => {
                            println!("Cannot parse test cases: {}", err);
                            process::exit(4);
                        }
                    },
                    Err(err) => {
                        println!("Cannot build validation spec: {}", err);
                        process::exit(3);
                    }
                },
                Err(err) => {
                    println!("Cannot build replacements: {}", err);
                    process::exit(5);
                }
            }

            /*let request = r#""#;
            match ValidationSpec::new(&spec, None){
                Ok(v_spec) => {
                    match validate_raw_request(&v_spec, request){
                        Ok(_) => println!("request OK"),
                        Err(err) => println!("request error: {err}"),
                    }
                }
                Err(err) => {
                    println!("Cannot build validation spec: {}", err);
                    process::exit(3);
                }
            }*/
        }
        Err(err) => {
            println!("Cannot parse spec: {}", err);
            process::exit(2);
        }
    }
}
