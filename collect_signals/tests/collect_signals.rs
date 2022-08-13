use std::collections::HashMap;
use collect_signals::collect_signals::CollectSignals;
use std::thread;
use std::time::Duration;
use std::borrow::Borrow;

#[test]
fn push_signal() {
    let mut cs = CollectSignals::<u8, String, String>::new();
    cs.insert_signal(10);
}

#[test]
fn pop_signal() {
    let mut cs = CollectSignals::<u8, String, String>::new();
    cs.insert_signal(10);
    assert_eq!(10, cs.extract_signal().unwrap())
}

#[test]
fn push_and_search() {
    let mut cs = CollectSignals::<u8, (String, String), String>::new();
    cs.insert_entry(("Steo".to_string(), "Steo".to_string()), "Albo".to_string());
    assert_eq!(cs.search_entry(("Steo".to_string(), "Steo".to_string())).unwrap(), "Albo".to_string());
}

#[test]
fn threads_signals(){
    let mut cs = CollectSignals::<((u32, u32), String), (u32, u32), String>::new();
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
                if command.is_none(){
                    return;
                }
                println!("{:?}, thread: {}",command.unwrap(),t);
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn threads_operate(){
    let mut cs = CollectSignals::<((u32, u32), String), (u32, u32), String>::new();
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
            println!("thread: {}",t);
            loop {
                let command = c.extract_signal();
                if command.is_none(){
                    //return;
                    continue;
                }
                if command.unwrap().0.0 == -1 {
                    return;
                }
                let mut hashmap = c.lock_hashmap();
                /*let e = c.search_entry((command.unwrap().0.0,command.unwrap().0.1));
                if e.is_some() && e.unwrap()<command.unwrap().1 || e.is_none(){
                    c.insert_collection((command.unwrap().0.0, command.unwrap().0.1), command.unwrap().1);
                }*/
                let e = hashmap.get(&(command.unwrap().0.0,command.unwrap().0.1));
                if e.is_some() && *e.unwrap()<command.unwrap().1 || e.is_none(){
                    hashmap.insert((command.unwrap().0.0, command.unwrap().0.1),command.unwrap().1);
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
            0 => {assert!(*e.1==96);},
            1 => {assert!(*e.1==97);},
            2 => {assert!(*e.1==98);},
            3 => {assert!(*e.1==99);},
            4 => {assert!(*e.1==92);},
            5 => {assert!(*e.1==93);},
            6 => {assert!(*e.1==94);},
            7 => {assert!(*e.1==95);},
            _ => {}
        }
    }
}

