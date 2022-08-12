pub mod hashmap_utils {
use std::sync::{Arc, Condvar, Mutex};
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;
    use std::hash::Hash;
    use std::ops::Deref;

    pub struct HashmapLock<K,V> {
        hashmap: Arc<Mutex<HashMap<K,V>>>,
    }

    impl<K: Eq + Hash,V> HashmapLock<K,V> {
        pub fn new() -> Self{
            HashmapLock{hashmap: Arc::new(Mutex::new(HashMap::<K,V>::new()))}
        }
    }

    impl<K,V> Deref for HashmapLock<K,V> {
        type Target = Arc<Mutex<HashMap<K,V>>>;

        fn deref(&self) -> &Self::Target {
            &self.hashmap
        }
    }

    impl<K,V> Clone for HashmapLock<K, V> {
        fn clone(&self) -> Self {
            HashmapLock{hashmap: self.hashmap.clone()}
        }
    }
}