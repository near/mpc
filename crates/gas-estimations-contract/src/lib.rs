#![allow(clippy::disallowed_types)]
use std::collections::HashMap;

use near_sdk::{
    near,
    store::{IterableMap, Lazy},
};

#[near(contract_state)]
pub struct Contract {
    std_hash_map: Lazy<HashMap<u32, u32>>,
    near_hash_map: IterableMap<u32, u32>,
    not_lazy_data: Vec<u8>,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            std_hash_map: Lazy::new(b"l", HashMap::default()),
            near_hash_map: IterableMap::new(b"h"),
            not_lazy_data: Vec::new(),
        }
    }
}

#[near]
impl Contract {
    pub fn get_number_of_life() -> u32 {
        42
    }

    pub fn noop() {}

    pub fn noop_with_self(&self) {}

    pub fn insert_many_std_hash_map(&mut self, elements: Vec<(u32, u32)>) {
        for (a, b) in elements {
            self.std_hash_map.get_mut().insert(a, b);
        }
    }

    pub fn insert_many_near_hash_map(&mut self, elements: Vec<(u32, u32)>) {
        for (a, b) in elements {
            self.near_hash_map.insert(a, b);
        }
    }

    pub fn get_from_std_hash_map(&self, element: u32) -> Option<u32> {
        self.std_hash_map.get().get(&element).cloned()
    }

    pub fn get_from_near_hash_map(&self, element: u32) -> Option<u32> {
        self.near_hash_map.get(&element).cloned()
    }

    pub fn update_from_std_hash_map(&mut self, a: u32, b: u32) -> Option<u32> {
        self.std_hash_map.get_mut().insert(a, b)
    }

    pub fn update_from_near_hash_map(&mut self, a: u32, b: u32) -> Option<u32> {
        self.near_hash_map.insert(a, b)
    }

    pub fn remove_from_std_hash_map(&mut self, a: u32) -> Option<u32> {
        self.std_hash_map.get_mut().remove(&a)
    }

    pub fn remove_from_near_hash_map(&mut self, a: u32) -> Option<u32> {
        self.near_hash_map.remove(&a)
    }

    pub fn clear_std_hash_map(&mut self) {
        self.std_hash_map.get_mut().clear();
    }

    pub fn clear_near_hash_map(&mut self) {
        self.near_hash_map.clear();
    }

    pub fn increase_self_loading_cost(&mut self, n: usize) {
        let slice = vec![0u8; n];
        self.not_lazy_data.extend_from_slice(&slice);
    }
}
