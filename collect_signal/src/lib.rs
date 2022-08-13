pub mod collect_signal {
    use std::collections::{HashMap, VecDeque};
    use std::hash::Hash;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    pub struct CollectSignal<S, K, V> {
        command_queue: Arc<Mutex<VecDeque<S>>>,
        collection: Arc<Mutex<HashMap<K, V>>>,
    }

    impl<S, K: Clone + Eq + Hash, V:  Clone + Eq + Hash> CollectSignal<S, K, V> {
        pub fn new() -> Self {
            return CollectSignal {
                command_queue: Arc::new(Mutex::new(VecDeque::<S>::new())),
                collection: Arc::new(Mutex::new(HashMap::<K, V>::new()))
            }
        }

        pub fn insert_command(&mut self, command: S) {
            let mut l = self.command_queue.lock().unwrap();
            l.push_back(command);
        }

        pub fn extract_command(&mut self) -> Option<S> {
            let mut l = self.command_queue.lock().unwrap();
            return l.pop_front();
        }

        pub fn insert_collection(&mut self, key: K, value: V) {
            let mut l = self.collection.lock().unwrap();
            l.insert(key, value);
        }

        pub fn search_entry(&mut self, key: K) -> Option<V> {
            let l = self.collection.lock().unwrap();
            return match l.get(&key) {
                None => None,
                value => Some(value.unwrap().clone())
            }
        }
    }
}