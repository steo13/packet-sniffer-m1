pub mod collect_signals {
    use std::collections::{HashMap, VecDeque};
    use std::env::Args;
    use std::hash::Hash;
    use std::sync::{Arc, Mutex, MutexGuard};

    #[derive(Clone)]
    pub struct CollectSignals<S, K, V> {
        command_queue: Arc<Mutex<VecDeque<S>>>,
        collection: Arc<Mutex<HashMap<K, V>>>,
    }

    impl<S, K: Clone + Eq + Hash, V:  Clone + Eq + Hash> CollectSignals<S, K, V> {
        pub fn new() -> Self {
            return CollectSignals {
                command_queue: Arc::new(Mutex::new(VecDeque::<S>::new())),
                collection: Arc::new(Mutex::new(HashMap::<K, V>::new()))
            }
        }

        pub fn insert_signal(&mut self, signal: S) {
            let mut l = self.command_queue.lock().unwrap();
            l.push_back(signal);
        }

        pub fn extract_signal(&mut self) -> Option<S> {
            let mut l = self.command_queue.lock().unwrap();
            return l.pop_front();
        }

        pub fn insert_entry(&mut self, key: K, value: V) {
            let mut l = self.collection.lock().unwrap();
            l.insert(key, value);
        }

        pub fn search_entry(&mut self, key: K) -> Option<V> {
            let mut l = self.collection.lock().unwrap();
            return match l.get(&key) {
                None => None,
                value => Some(value.unwrap().clone())
            }
        }

        pub fn produce_hashmap(self) -> HashMap<K,V> {
            let l = self.collection.lock().unwrap();
            return l.clone()
        }

        pub fn lock_hashmap(&mut self) -> MutexGuard<HashMap<K,V>> {
            return self.collection.lock().unwrap()
        }
    }
}