fn process_order(items: Vec<&str>) -> String {
    let total: Option<u32>;
    if items.is_empty() {
        total = None; // BUG: total is None, used as u32 below
    } else {
        total = Some(items.len() as u32 * 10);
    }
    format!("Total: {}", total.unwrap() + 5) // panics: unwrap on None
}

fn main() {
    let _ = helper();
    let result = process_order(vec![]);
    println!("{}", result);
}

fn helper() -> u32 {
    let multiplier = 2;
    multiplier
}
