pub mod collect_signals {
    use std::collections::{HashMap, VecDeque};
    use std::hash::Hash;
    use std::sync::{Arc, Mutex, MutexGuard, Condvar};

    #[derive(Clone)]
    pub struct CollectSignals<S, K, V> {
        command_queue: Arc<(Mutex<VecDeque<S>>,Condvar)>,
        collection: Arc<Mutex<HashMap<K, V>>>,
    }

    impl<S, K: Clone + Eq + Hash, V:  Clone + Eq + Hash> CollectSignals<S, K, V> {
        pub fn new() -> Self {
            return CollectSignals {
                command_queue: Arc::new((Mutex::new(VecDeque::<S>::new()),Condvar::new())),
                collection: Arc::new(Mutex::new(HashMap::<K, V>::new()))
            }
        }

        pub fn insert_signal(&mut self, signal: S) {
            let mut l = self.command_queue.0.lock().unwrap();
            l.push_back(signal);
            self.command_queue.1.notify_one();
        }

        pub fn extract_signal(&mut self) -> S {
            let mut l = self.command_queue.0.lock().unwrap();
            let mut res = self.command_queue.1.wait_while(l, |x| x.is_empty()).unwrap();
            return res.pop_front().unwrap();
        }

        pub fn insert_entry(&mut self, key: K, value: V) {
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

        pub fn produce_hashmap(&self) -> HashMap<K,V> {
            let l = self.collection.lock().unwrap();
            return l.clone()
        }

        pub fn lock_hashmap(&mut self) -> MutexGuard<HashMap<K,V>> {
            return self.collection.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::collect_signals::collect_signals::CollectSignals;
    use std::thread;

    #[test]
    fn push_signal() {
        let mut cs = CollectSignals::<u8, String, String>::new();
        cs.insert_signal(10);
    }

    #[test]
    fn pop_signal() {
        let mut cs = CollectSignals::<u8, String, String>::new();
        cs.insert_signal(10);
        assert_eq!(10, cs.extract_signal())
    }

    #[test]
    fn push_and_search() {
        let mut cs = CollectSignals::<u8, (String, String), String>::new();
        cs.insert_entry(("Steo".to_string(), "Steo".to_string()), "Albo".to_string());
        assert_eq!(cs.search_entry(("Steo".to_string(), "Steo".to_string())).unwrap(), "Albo".to_string());
    }

    #[test]
    fn threads_signals(){
        let mut cs = CollectSignals::<((i32, i32), String), (i32, i32), String>::new();
        let mut threads = vec![];
        for i in 0..100 {
            cs.insert_signal(((i,i),"prova".to_string()));
        }
        for t in 0..5 {
            let mut c = cs.clone();
            threads.push(thread::spawn(move||{
                println!("thread: {}",t);
                loop {
                    let command = c.extract_signal();
                    if command.0.0 == -1 {
                        return;
                    }
                    println!("{:?}, thread: {}",command,t);
                }
            }));
        }
        for _ in 0..5 {
            cs.insert_signal(((-1,1),"".to_string()));
        }
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn threads_operate(){
        let mut cs = CollectSignals::<((i32, i32), String), (u32, u32), String>::new();
        let mut threads = vec![];
        for i in 0..100 {
            cs.insert_entry((i,i),"prova".to_string());
        }
        for t in 0..5 {
            let mut c = cs.clone();
            threads.push(thread::spawn(move||{
                println!("thread: {}",t);
                for i in 0..102 {
                    let res = c.search_entry((i,i));
                    if res.is_none() {
                        assert!(i>=100);
                    }
                }
            }));
        }
        for _ in 0..5 {
            cs.insert_signal(((-1,1),"".to_string()));
        }
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn threads_complete(){
        let mut cs = CollectSignals::<((i32, i32), i32), (i32, i32), i32>::new();
        let mut threads = vec![];
        for i in 0..100 {
            cs.insert_signal(((i%8,i%8),i));
        }
        for t in 0..5 {
            let mut c = cs.clone();
            threads.push(thread::spawn(move||{
                loop {
                    println!("not locked");
                    let command = c.extract_signal();
                    if command.0.0 == -1 {
                        return;
                    }
                    let mut hashmap = c.lock_hashmap();
                    /*let e = c.search_entry((command.unwrap().0.0,command.unwrap().0.1));
                    if e.is_some() && e.unwrap()<command.unwrap().1 || e.is_none(){
                        c.insert_collection((command.unwrap().0.0, command.unwrap().0.1), command.unwrap().1);
                    }*/
                    let e = hashmap.get(&(command.0.0,command.0.1));
                    if e.is_some() && *e.unwrap()<command.1 || e.is_none(){
                        hashmap.insert((command.0.0, command.0.1),command.1);
                    }
                }
            }));
        }
        for _ in 0..5 {
            cs.insert_signal(((-1,1),-1));
        }
        for t in threads {
            t.join().unwrap();
        }
        let hm = cs.produce_hashmap();
        for e in hm.iter() {
            let k = *e.0;
            match k.0 {
                0 => { assert_eq!(*e.1, 96);},
                1 => { assert_eq!(*e.1, 97);},
                2 => { assert_eq!(*e.1, 98);},
                3 => { assert_eq!(*e.1, 99);},
                4 => { assert_eq!(*e.1, 92);},
                5 => { assert_eq!(*e.1, 93);},
                6 => { assert_eq!(*e.1, 94);},
                7 => { assert_eq!(*e.1, 95);},
                _ => {}
            }
        }
    }
}