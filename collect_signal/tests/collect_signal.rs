use collect_signal::collect_signal::CollectSignal;

#[test]
fn define_collection() {
    let _ = CollectSignal::<String, u8, u8>::new();
}

#[test]
fn push_signal() {
    let mut cs = CollectSignal::<u8, String, String>::new();
    cs.insert_command(10);
}

#[test]
fn pop_signal() {
    let mut cs = CollectSignal::<u8, String, String>::new();
    cs.insert_command(10);
    assert_eq!(10, cs.extract_command().unwrap())
}

#[test]
fn push_and_search() {
    let mut cs = CollectSignal::<u8, (String, String), String>::new();
    cs.insert_collection(("Steo".to_string(), "Steo".to_string()), "Albo".to_string());
    assert_eq!(cs.search_entry(("Steo".to_string(), "Steo".to_string())).unwrap(), "Albo".to_string());
}