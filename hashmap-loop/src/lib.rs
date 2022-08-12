mod hashmap_loop {
use std::sync::{Arc, Condvar, Mutex};

    pub struct HashmapLoop<K,V> {
        rc: Arc<(Mutex<Hashmap<K,V>>)>
    }
}