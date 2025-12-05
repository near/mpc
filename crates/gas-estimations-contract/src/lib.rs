#![allow(clippy::disallowed_types)]
use std::collections::HashMap;

use near_sdk::{env, near, store::IterableMap};

#[near(contract_state)]
pub struct Contract {
    std_hash_map: HashMap<u32, Vec<u32>>,
    near_hash_map: IterableMap<u32, Vec<u32>>,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            std_hash_map: Default::default(),
            near_hash_map: IterableMap::new(b"h"),
        }
    }
}

#[near]
impl Contract {
    pub fn get_number_of_life() -> u32 {
        42
    }

    pub fn insert_many_std_hash_map(&mut self, elements: Vec<(u32, Vec<u32>)>) {
        self.std_hash_map = HashMap::new();
        for (a, b) in elements {
            self.std_hash_map.insert(a, b);
        }
    }

    pub fn insert_many_near_hash_map(&mut self, elements: Vec<(u32, Vec<u32>)>) {
        for (a, b) in elements {
            self.near_hash_map.insert(a, b);
        }
    }

    pub fn get_from_std_hash_map(&self, element: u32) -> Option<Vec<u32>> {
        self.std_hash_map.get(&element).cloned()
    }

    pub fn get_from_near_hash_map(&self, element: u32) -> Option<Vec<u32>> {
        self.near_hash_map.get(&element).cloned()
    }

    pub fn update_from_std_hash_map(&mut self, a: u32, b: Vec<u32>) -> Option<Vec<u32>> {
        self.std_hash_map.insert(a, b)
    }

    pub fn update_from_near_hash_map(&mut self, a: u32, b: Vec<u32>) -> Option<Vec<u32>> {
        self.near_hash_map.insert(a, b)
    }

    pub fn remove_from_std_hash_map(&mut self, a: u32) -> Option<Vec<u32>> {
        self.std_hash_map.remove(&a)
    }

    pub fn remove_from_near_hash_map(&mut self, a: u32) -> Option<Vec<u32>> {
        self.near_hash_map.remove(&a)
    }
}
