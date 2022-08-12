use hashmap_lock::hashmap_lock::HashmapLock;
use std::thread;

#[test]
fn test_empty() {
    let hmap: HashmapLock<(),()> = HashmapLock::new();
    assert_eq!(hmap.lock().unwrap().is_empty(),true);
}

#[test]
fn test_get() {
    let hmap= HashmapLock::<u32,u32>::new();
    let mut hashmap = hmap.clone();
    {
        let mut map = hashmap.lock().unwrap();
        map.insert(0,0);
        map.insert(1,1);
    }
    for _ in 0..2{
        let hashmap = hmap.clone();
        let _ = thread::spawn(move || {
            let map = hashmap.lock().unwrap();
            assert_eq!(map.get(&0),Some(&0));
            assert_eq!(map.get(&1),Some(&1));
            assert_eq!(map.get(&2),None);
        });
    }
}

#[test]
fn test_insert() {
    let hmap = HashmapLock::<u32, u32>::new();
    let mut threads = vec![];
    for i in 0..2 {
        let hashmap = hmap.clone();
        let t = thread::spawn(move || {
            let mut map = hashmap.lock().unwrap();
            map.insert(i, i);
        });
        threads.push(t);
    }
    for t in threads{
        t.join().unwrap();
    }
    let hashmap = hmap.clone();
    let map = hashmap.lock().unwrap();
    assert_eq!(map.get(&0),Some(&0));
    assert_eq!(map.get(&1),Some(&1));
    assert_eq!(map.get(&2),None);
}
