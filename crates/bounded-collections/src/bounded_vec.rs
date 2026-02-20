use std::{
    convert::{TryFrom, TryInto},
    slice::{Iter, IterMut},
    vec,
};

use thiserror::Error;

/// Vec bounded with minimal (L - lower bound) and maximal (U - upper bound) items quantity.
///
/// By default the witness type is [`witnesses::NonEmpty`], which requires `L > 0`.
/// For a possibly-empty bounded vector (where `L = 0`), use [`EmptyBoundedVec`] instead.
///
/// # Type Parameters
///
/// * `W` - witness type to prove vector ranges and shape of interface accordingly
#[derive(PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
pub struct BoundedVec<T, const L: usize, const U: usize, W = witnesses::NonEmpty<L, U>> {
    inner: Vec<T>,
    witness: W,
}

/// BoundedVec errors
#[derive(Error, PartialEq, Eq, Debug, Clone)]
pub enum BoundedVecOutOfBounds {
    /// Items quantity is less than L (lower bound)
    #[error("Lower bound violation: got {got} (expected >= {lower_bound})")]
    LowerBoundError {
        /// L (lower bound)
        lower_bound: usize,
        /// provided value
        got: usize,
    },
    /// Items quantity is more than U (upper bound)
    #[error("Upper bound violation: got {got} (expected <= {upper_bound})")]
    UpperBoundError {
        /// U (upper bound)
        upper_bound: usize,
        /// provided value
        got: usize,
    },
}

/// Module for type witnesses used to prove vector bounds at compile time
pub mod witnesses {
    /// Compile-time proof of valid bounds. Must be constructed with same bounds to instantiate `BoundedVec`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct NonEmpty<const L: usize, const U: usize>(
        (), // private field to prevent direct construction.
    );

    /// Possibly empty vector with upper bound.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct PossiblyEmpty<const U: usize>(
        (), // private field to prevent direct construction.
    );

    /// Type a compile-time proof of valid bounds
    pub const fn non_empty<const L: usize, const U: usize>() -> NonEmpty<L, U> {
        const {
            if L == 0 {
                panic!("L must be greater than 0")
            }
            if L > U {
                panic!("L must be less than or equal to U")
            }

            NonEmpty::<L, U>(())
        }
    }

    /// Type a compile-time proof for possibly empty vector with upper bound
    pub const fn possibly_empty<const U: usize>() -> PossiblyEmpty<U> {
        const { PossiblyEmpty::<U>(()) }
    }
}

impl<T, const U: usize> BoundedVec<T, 0, U, witnesses::PossiblyEmpty<U>> {
    /// Creates new [`BoundedVec`] or returns error if items count is out of bounds
    ///
    /// # Parameters
    ///
    /// * `items` - vector of items within bounds
    ///
    /// # Errors
    ///
    /// * `UpperBoundError` - if `items` len is more than U (upper bound)
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use bounded_collections::witnesses;
    /// let data: BoundedVec<_, 0, 8, witnesses::PossiblyEmpty<8>> =
    ///     BoundedVec::<_, 0, 8, witnesses::PossiblyEmpty<8>>::from_vec(vec![1u8, 2]).unwrap();
    /// ```
    pub fn from_vec(items: Vec<T>) -> Result<Self, BoundedVecOutOfBounds> {
        let witness = witnesses::possibly_empty::<U>();
        let len = items.len();
        if len > U {
            Err(BoundedVecOutOfBounds::UpperBoundError {
                upper_bound: U,
                got: len,
            })
        } else {
            Ok(BoundedVec {
                inner: items,
                witness,
            })
        }
    }

    /// Returns the first element of the vector, or [`None`] if it is empty
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use bounded_collections::witnesses;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<u8, 0, 8, witnesses::PossiblyEmpty<8>> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(data.first(), Some(&1u8));
    /// ```
    pub fn first(&self) -> Option<&T> {
        self.inner.first()
    }

    /// Returns `true` if the vector contains no elements
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use bounded_collections::witnesses;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<u8, 0, 8, witnesses::PossiblyEmpty<8>> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(data.is_empty(), false);
    /// ```
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the last element of the vector, or [`None`] if it is empty
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use bounded_collections::witnesses;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<u8, 0, 8, witnesses::PossiblyEmpty<8>> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(data.last(), Some(&2u8));
    /// ```
    pub fn last(&self) -> Option<&T> {
        self.inner.last()
    }
}

/// Methods which works for all witnesses
impl<T, const L: usize, const U: usize, W> BoundedVec<T, L, U, W> {
    /// Returns an underlying [`Vec`]
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(data.into_vec(), vec![1u8,2]);
    /// ```
    pub fn into_vec(self) -> Vec<T> {
        self.inner
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(data.as_slice(), &[1u8,2]);
    /// ```
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Returns a reference for an element at index or `None` if out of bounds
    ///
    /// # Example
    ///
    /// ```
    /// use bounded_collections::BoundedVec;
    /// let data: BoundedVec<u8, 2, 8> = [1u8,2].into();
    /// let elem = *data.get(1).unwrap();
    /// assert_eq!(elem, 2);
    /// ```
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Returns the number of elements in the vector
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<u8, 2, 4> = vec![1u8,2].try_into().unwrap();
    /// assert_eq!(data.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns an iterator
    pub fn iter(&self) -> Iter<T> {
        self.inner.iter()
    }

    /// Returns an iterator that allows to modify each value
    pub fn iter_mut(&mut self) -> IterMut<T> {
        self.inner.iter_mut()
    }
}

impl<T, const L: usize, const U: usize> BoundedVec<T, L, U, witnesses::NonEmpty<L, U>> {
    /// Creates new BoundedVec or returns error if items count is out of bounds
    ///
    /// # Parameters
    ///
    /// * `items` - vector of items within bounds
    ///
    /// # Errors
    ///
    /// * `LowerBoundError` - if `items` len is less than L (lower bound)
    /// * `UpperBoundError` - if `items` len is more than U (upper bound)
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use bounded_collections::witnesses;
    /// let data: BoundedVec<_, 2, 8, witnesses::NonEmpty<2, 8>> =
    ///     BoundedVec::<_, 2, 8, witnesses::NonEmpty<2, 8>>::from_vec(vec![1u8, 2]).unwrap();
    /// ```
    pub fn from_vec(items: Vec<T>) -> Result<Self, BoundedVecOutOfBounds> {
        let witness = witnesses::non_empty::<L, U>();
        let len = items.len();
        if len < L {
            Err(BoundedVecOutOfBounds::LowerBoundError {
                lower_bound: L,
                got: len,
            })
        } else if len > U {
            Err(BoundedVecOutOfBounds::UpperBoundError {
                upper_bound: U,
                got: len,
            })
        } else {
            Ok(BoundedVec {
                inner: items,
                witness,
            })
        }
    }

    /// Returns the first element of non-empty Vec
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(*data.first(), 1);
    /// ```
    pub fn first(&self) -> &T {
        self.inner.first().unwrap()
    }

    /// Returns the last element of non-empty Vec
    ///
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use std::convert::TryInto;
    ///
    /// let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
    /// assert_eq!(*data.last(), 2);
    /// ```
    pub fn last(&self) -> &T {
        self.inner.last().unwrap()
    }

    /// Create a new `BoundedVec` by consuming `self` and mapping each element.
    ///
    /// This is useful as it keeps the knowledge that the length is >= L, <= U,
    /// even through the old `BoundedVec` is consumed and turned into an iterator.
    ///
    /// # Example
    ///
    /// ```
    /// use bounded_collections::BoundedVec;
    /// let data: BoundedVec<u8, 2, 8> = [1u8,2].into();
    /// let data = data.mapped(|x|x*2);
    /// assert_eq!(data, [2u8,4].into());
    /// ```
    pub fn mapped<F, N>(self, map_fn: F) -> BoundedVec<N, L, U, witnesses::NonEmpty<L, U>>
    where
        F: FnMut(T) -> N,
    {
        BoundedVec {
            inner: self.inner.into_iter().map(map_fn).collect::<Vec<_>>(),
            witness: self.witness,
        }
    }

    /// Create a new `BoundedVec` by mapping references to the elements of self
    ///
    /// This is useful as it keeps the knowledge that the length is >= L, <= U,
    /// will still hold for new `BoundedVec`
    ///
    /// # Example
    ///
    /// ```
    /// use bounded_collections::BoundedVec;
    /// let data: BoundedVec<u8, 2, 8> = [1u8,2].into();
    /// let data = data.mapped_ref(|x|x*2);
    /// assert_eq!(data, [2u8,4].into());
    /// ```
    pub fn mapped_ref<F, N>(&self, map_fn: F) -> BoundedVec<N, L, U, witnesses::NonEmpty<L, U>>
    where
        F: FnMut(&T) -> N,
    {
        BoundedVec {
            inner: self.inner.iter().map(map_fn).collect::<Vec<_>>(),
            witness: self.witness,
        }
    }

    /// Create a new `BoundedVec` by consuming `self` and mapping each element
    /// to a `Result`.
    ///
    /// This is useful as it keeps the knowledge that the length is preserved
    /// even through the old `BoundedVec` is consumed and turned into an iterator.
    ///
    /// As this method consumes self, returning an error means that this
    /// vec is dropped. I.e. this method behaves roughly like using a
    /// chain of `into_iter()`, `map`, `collect::<Result<Vec<N>,E>>` and
    /// then converting the `Vec` back to a `Vec1`.
    ///
    ///
    /// # Errors
    ///
    /// Once any call to `map_fn` returns a error that error is directly
    /// returned by this method.
    ///
    /// # Example
    ///
    /// ```
    /// use bounded_collections::BoundedVec;
    /// let data: BoundedVec<u8, 2, 8> = [1u8,2].into();
    /// let data: Result<BoundedVec<u8, 2, 8>, _> = data.try_mapped(|x| Err("failed"));
    /// assert_eq!(data, Err("failed"));
    /// ```
    pub fn try_mapped<F, N, E>(
        self,
        mut map_fn: F,
    ) -> Result<BoundedVec<N, L, U, witnesses::NonEmpty<L, U>>, E>
    where
        F: FnMut(T) -> Result<N, E>,
    {
        let out = self
            .inner
            .into_iter()
            .map(&mut map_fn)
            .collect::<Result<Vec<_>, E>>()?;

        Ok(BoundedVec {
            inner: out,
            witness: self.witness,
        })
    }

    /// Create a new `BoundedVec` by mapping references of `self` elements
    /// to a `Result`.
    ///
    /// This is useful as it keeps the knowledge that the length is preserved
    /// even through the old `BoundedVec` is consumed and turned into an iterator.
    ///
    /// # Errors
    ///
    /// Once any call to `map_fn` returns a error that error is directly
    /// returned by this method.
    ///
    /// # Example
    ///
    /// ```
    /// use bounded_collections::BoundedVec;
    /// let data: BoundedVec<u8, 2, 8> = [1u8,2].into();
    /// let data: Result<BoundedVec<u8, 2, 8>, _> = data.try_mapped_ref(|x| Err("failed"));
    /// assert_eq!(data, Err("failed"));
    /// ```
    pub fn try_mapped_ref<F, N, E>(
        &self,
        mut map_fn: F,
    ) -> Result<BoundedVec<N, L, U, witnesses::NonEmpty<L, U>>, E>
    where
        F: FnMut(&T) -> Result<N, E>,
    {
        let out = self
            .inner
            .iter()
            .map(&mut map_fn)
            .collect::<Result<Vec<_>, E>>()?;

        Ok(BoundedVec {
            inner: out,
            witness: self.witness,
        })
    }

    /// Returns the last and all the rest of the elements
    pub fn split_last(&self) -> (&T, &[T]) {
        self.inner.split_last().unwrap()
    }

    /// Return a new BoundedVec with indices included
    pub fn enumerated(self) -> BoundedVec<(usize, T), L, U, witnesses::NonEmpty<L, U>> {
        BoundedVec {
            inner: self.inner.into_iter().enumerate().collect(),
            witness: self.witness,
        }
    }

    /// Return a Some(BoundedVec) or None if `v` is empty
    /// # Example
    /// ```
    /// use bounded_collections::BoundedVec;
    /// use bounded_collections::OptBoundedVecToVec;
    ///
    /// let opt_bv_none = BoundedVec::<u8, 2, 8>::opt_empty_vec(vec![]).unwrap();
    /// assert!(opt_bv_none.is_none());
    /// assert_eq!(opt_bv_none.to_vec(), Vec::<u8>::new());
    /// let opt_bv_some = BoundedVec::<u8, 2, 8>::opt_empty_vec(vec![0u8, 2]).unwrap();
    /// assert!(opt_bv_some.is_some());
    /// assert_eq!(opt_bv_some.to_vec(), vec![0u8, 2]);
    /// ```
    pub fn opt_empty_vec(
        v: Vec<T>,
    ) -> Result<Option<BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>>, BoundedVecOutOfBounds> {
        if v.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self::from_vec(v)?))
        }
    }
}

/// A non-empty Vec with no effective upper-bound on its length
pub type NonEmptyVec<T> = BoundedVec<T, 1, { usize::MAX }, witnesses::NonEmpty<1, { usize::MAX }>>;

/// Possibly empty Vec with upper-bound on its length
pub type EmptyBoundedVec<T, const U: usize> = BoundedVec<T, 0, U, witnesses::PossiblyEmpty<U>>;

/// Non-empty Vec with bounded length
pub type NonEmptyBoundedVec<T, const L: usize, const U: usize> =
    BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>;

impl<T, const L: usize, const U: usize> TryFrom<Vec<T>>
    for BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>
{
    type Error = BoundedVecOutOfBounds;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}

impl<T, const U: usize> TryFrom<Vec<T>> for BoundedVec<T, 0, U, witnesses::PossiblyEmpty<U>> {
    type Error = BoundedVecOutOfBounds;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}

// when feature(const_evaluatable_checked) is stable cover all array sizes (L..=U)
impl<T, const L: usize, const U: usize> From<[T; L]>
    for BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>
{
    fn from(arr: [T; L]) -> Self {
        BoundedVec {
            inner: arr.into(),
            witness: witnesses::non_empty(),
        }
    }
}

impl<T, const L: usize, const U: usize> From<BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>>
    for Vec<T>
{
    fn from(v: BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>) -> Self {
        v.inner
    }
}

impl<T, const U: usize> From<BoundedVec<T, 0, U, witnesses::PossiblyEmpty<U>>> for Vec<T> {
    fn from(v: BoundedVec<T, 0, U, witnesses::PossiblyEmpty<U>>) -> Self {
        v.inner
    }
}

impl<T, const L: usize, const U: usize, W> IntoIterator for BoundedVec<T, L, U, W> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T, const L: usize, const U: usize, W> IntoIterator for &'a BoundedVec<T, L, U, W> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T, const L: usize, const U: usize, W> IntoIterator for &'a mut BoundedVec<T, L, U, W> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<T, const L: usize, const U: usize, W> AsRef<Vec<T>> for BoundedVec<T, L, U, W> {
    fn as_ref(&self) -> &Vec<T> {
        &self.inner
    }
}

impl<T, const L: usize, const U: usize, W> AsRef<[T]> for BoundedVec<T, L, U, W> {
    fn as_ref(&self) -> &[T] {
        self.inner.as_slice()
    }
}

/// `AsRef<[T; N]>` is only available when `L == U == N`, i.e. the vector has
/// a fixed length known at compile time.
///
/// ```
/// use bounded_collections::BoundedVec;
/// let data: BoundedVec<u8, 3, 3> = [1u8, 2, 3].into();
/// let arr: &[u8; 3] = data.as_ref();
/// assert_eq!(arr, &[1, 2, 3]);
/// ```
///
/// Does not compile when L != U (variable-length vec):
/// ```compile_fail,E0277
/// use bounded_collections::BoundedVec;
/// let data: BoundedVec<u8, 2, 8> = vec![1u8, 2].try_into().unwrap();
/// let _: &[u8; 2] = data.as_ref();
/// ```
///
/// Does not compile when N differs from L and U:
/// ```compile_fail,E0277
/// use bounded_collections::BoundedVec;
/// let data: BoundedVec<u8, 3, 3> = [1u8, 2, 3].into();
/// let _: &[u8; 4] = data.as_ref();
/// ```
impl<T, const N: usize> AsRef<[T; N]> for BoundedVec<T, N, N, witnesses::NonEmpty<N, N>> {
    fn as_ref(&self) -> &[T; N] {
        self.inner.as_slice().try_into().expect(
            "When L == U == N, the length is guaranteed to be exactly N, so the conversion to a fixed-size array is infallible",
        )
    }
}

/// [`Option<BoundedVec<T, _, _>>`] to [`Vec<T>`]
pub trait OptBoundedVecToVec<T> {
    /// [`Option<BoundedVec<T, _, _>>`] to [`Vec<T>`]
    fn to_vec(self) -> Vec<T>;
}

impl<T, const L: usize, const U: usize> OptBoundedVecToVec<T>
    for Option<BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>>
{
    fn to_vec(self) -> Vec<T> {
        self.map(|bv| bv.into()).unwrap_or_default()
    }
}

mod borsh_impl {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};

    impl<T: BorshSerialize, const L: usize, const U: usize, W> BorshSerialize
        for BoundedVec<T, L, U, W>
    {
        fn serialize<Writer: std::io::Write>(&self, writer: &mut Writer) -> std::io::Result<()> {
            self.inner.serialize(writer)
        }
    }

    impl<T: BorshDeserialize, const L: usize, const U: usize> BorshDeserialize
        for BoundedVec<T, L, U, witnesses::NonEmpty<L, U>>
    {
        fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
            let inner = Vec::<T>::deserialize_reader(reader)?;
            Self::from_vec(inner)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        }
    }

    impl<T: BorshDeserialize, const U: usize> BorshDeserialize
        for BoundedVec<T, 0, U, witnesses::PossiblyEmpty<U>>
    {
        fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
            let inner = Vec::<T>::deserialize_reader(reader)?;
            Self::from_vec(inner)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        }
    }

    #[cfg(feature = "abi")]
    mod schema {
        use super::*;
        use borsh::BorshSchema;
        use borsh::schema::{Declaration, Definition, add_definition};
        use std::collections::BTreeMap;

        impl<T: BorshSchema, const L: usize, const U: usize, W> BorshSchema for BoundedVec<T, L, U, W> {
            fn declaration() -> Declaration {
                format!("BoundedVec<{}, {}, {}>", T::declaration(), L, U)
            }

            fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
                let definition = Definition::Sequence {
                    length_width: Definition::DEFAULT_LENGTH_WIDTH,
                    length_range: (L as u64)..=(U as u64),
                    elements: T::declaration(),
                };
                add_definition(Self::declaration(), definition, definitions);
                T::add_definitions_recursively(definitions);
            }
        }
    }
}

mod serde_impl {
    use super::*;
    use serde::{Deserialize, Serialize};

    // direct impl to unify serde in one place instead of doing attribute on declaration and deserialize here
    impl<T: Serialize, const L: usize, const U: usize, W> Serialize for BoundedVec<T, L, U, W> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.inner.serialize(serializer)
        }
    }

    impl<'de, T: Deserialize<'de>, const L: usize, const U: usize> Deserialize<'de>
        for BoundedVec<T, L, U>
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let inner = Vec::<T>::deserialize(deserializer)?;
            BoundedVec::<T, L, U>::from_vec(inner).map_err(serde::de::Error::custom)
        }
    }

    impl<'de, T: Deserialize<'de>, const U: usize> Deserialize<'de> for EmptyBoundedVec<T, U> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let inner = Vec::<T>::deserialize(deserializer)?;
            EmptyBoundedVec::from_vec(inner).map_err(serde::de::Error::custom)
        }
    }

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    mod schema {
        use super::*;
        use schemars::JsonSchema;

        impl<T: JsonSchema, const L: usize, const U: usize, W> JsonSchema for BoundedVec<T, L, U, W> {
            fn schema_name() -> String {
                format!("BoundedVec_{}_Min{}_Max{}", T::schema_name(), L, U)
            }

            fn json_schema(
                generator: &mut schemars::r#gen::SchemaGenerator,
            ) -> schemars::schema::Schema {
                let mut schema = <Vec<T>>::json_schema(generator);
                if let schemars::schema::Schema::Object(ref mut obj) = schema {
                    if let Some(ref mut array) = obj.array {
                        array.min_items = u32::try_from(L).ok();
                        array.max_items = u32::try_from(U).ok();
                    }
                }
                schema
            }
        }
    }
}

/// Serde helper for serializing/deserializing `BoundedVec<u8, L, U>` as a hex string.
///
/// Use with `#[serde(with = "bounded_collections::hex_serde")]` on fields
/// whose type is `BoundedVec<u8, L, U>`.
///
/// When the `abi` feature is enabled, pair with
/// `#[schemars(with = "bounded_collections::hex_serde::HexString<L, U>")]`
/// to generate a string schema with hex length constraints.
///
/// # Example
/// ```ignore
/// use bounded_collections::BoundedVec;
///
/// #[derive(serde::Serialize, serde::Deserialize)]
/// #[cfg_attr(feature = "abi", derive(schemars::JsonSchema))]
/// struct MyStruct {
///     #[serde(with = "bounded_collections::hex_serde")]
///     #[cfg_attr(feature = "abi", schemars(with = "bounded_collections::hex_serde::HexString<1, 64>"))]
///     data: BoundedVec<u8, 1, 64>,
/// }
/// ```
pub mod hex_serde {
    use super::*;
    use serde::Deserialize;

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    const HEX_PATTERN: &str = "^[0-9a-fA-F]*$";

    pub fn serialize<S, const L: usize, const U: usize, W>(
        value: &BoundedVec<u8, L, U, W>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(value.as_slice()))
    }

    pub fn deserialize<'de, D, const L: usize, const U: usize>(
        deserializer: D,
    ) -> Result<BoundedVec<u8, L, U>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(serde::de::Error::custom)
    }

    /// Marker type for JSON schema generation of hex-encoded `BoundedVec<u8, L, U>`.
    ///
    /// Use with `#[schemars(with = "bounded_collections::hex_serde::HexString<L, U>")]`
    /// alongside `#[serde(with = "bounded_collections::hex_serde")]`.
    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    pub struct HexString<const L: usize, const U: usize>;

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    impl<const L: usize, const U: usize> schemars::JsonSchema for HexString<L, U> {
        fn schema_name() -> String {
            format!("HexString_Min{}_Max{}", L, U)
        }

        fn json_schema(
            _generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            schemars::schema::SchemaObject {
                instance_type: Some(schemars::schema::InstanceType::String.into()),
                string: Some(Box::new(schemars::schema::StringValidation {
                    min_length: Some((L * 2) as u32),
                    max_length: Some((U * 2) as u32),
                    pattern: Some(HEX_PATTERN.to_string()),
                })),
                ..Default::default()
            }
            .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use core::convert::TryInto;

    use super::*;

    #[test]
    fn from_vec_succeeds_within_bounds() {
        // Given
        let items = vec![1u8, 2];
        // When
        let result = BoundedVec::<u8, 2, 8>::from_vec(items);
        // Then
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn from_vec_fails_below_lower_bound() {
        // Given
        let empty: Vec<u8> = vec![];
        // When
        let result = BoundedVec::<u8, 2, 8>::from_vec(empty);
        // Then
        assert_eq!(
            result.unwrap_err(),
            BoundedVecOutOfBounds::LowerBoundError {
                lower_bound: 2,
                got: 0,
            }
        );
    }

    #[test]
    fn from_vec_fails_when_length_less_than_lower_bound() {
        // Given
        let items = vec![1u8, 2];
        // When
        let result = BoundedVec::<u8, 3, 8>::from_vec(items);
        // Then
        assert_eq!(
            result.unwrap_err(),
            BoundedVecOutOfBounds::LowerBoundError {
                lower_bound: 3,
                got: 2,
            }
        );
    }

    #[test]
    fn from_vec_fails_above_upper_bound() {
        // Given
        let items = vec![1u8, 2, 3];
        // When
        let result = BoundedVec::<u8, 1, 2>::from_vec(items);
        // Then
        assert_eq!(
            result.unwrap_err(),
            BoundedVecOutOfBounds::UpperBoundError {
                upper_bound: 2,
                got: 3,
            }
        );
    }

    #[test]
    fn empty_bounded_from_vec_succeeds_within_bounds() {
        // Given
        let items = vec![1u8, 2];
        // When
        let result = EmptyBoundedVec::<u8, 8>::from_vec(items);
        // Then
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn empty_bounded_from_vec_accepts_empty() {
        // Given
        let items: Vec<u8> = vec![];
        // When
        let result = EmptyBoundedVec::<u8, 8>::from_vec(items);
        // Then
        assert_eq!(
            result,
            Ok(BoundedVec {
                inner: vec![],
                witness: witnesses::possibly_empty()
            })
        );
    }

    #[test]
    fn empty_bounded_from_vec_fails_above_upper_bound() {
        // Given
        let items = vec![1u8, 2, 3];
        // When
        let result = EmptyBoundedVec::<u8, 2>::from_vec(items);
        // Then
        assert_eq!(
            result.unwrap_err(),
            BoundedVecOutOfBounds::UpperBoundError {
                upper_bound: 2,
                got: 3,
            }
        );
    }

    #[test]
    fn is_empty_returns_false_for_non_empty_vec() {
        // Given
        let data: EmptyBoundedVec<_, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert!(!data.is_empty());
    }

    #[test]
    fn as_slice_returns_slice_of_elements() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert_eq!(data.as_slice(), &[1u8, 2]);
    }

    #[test]
    fn len_returns_element_count() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert_eq!(data.len(), 2);
    }

    #[test]
    fn first_returns_first_element() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert_eq!(data.first(), &1u8);
    }

    #[test]
    fn last_returns_last_element() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert_eq!(data.last(), &2u8);
    }

    #[test]
    fn empty_bounded_first_returns_some_when_non_empty() {
        // Given
        let data: EmptyBoundedVec<_, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert_eq!(data.first(), Some(&1u8));
    }

    #[test]
    fn empty_bounded_last_returns_some_when_non_empty() {
        // Given
        let data: EmptyBoundedVec<_, 8> = vec![1u8, 2].try_into().unwrap();
        // When / Then
        assert_eq!(data.last(), Some(&2u8));
    }

    #[test]
    fn mapped_applies_function_to_all_elements() {
        // Given
        let data: BoundedVec<u8, 2, 8> = [1u8, 2].into();
        // When
        let result = data.mapped(|x| x * 2);
        // Then
        assert_eq!(result, [2u8, 4].into());
    }

    #[test]
    fn mapped_ref_applies_function_to_all_elements() {
        // Given
        let data: BoundedVec<u8, 2, 8> = [1u8, 2].into();
        // When
        let result = data.mapped_ref(|x| x * 2);
        // Then
        assert_eq!(result, [2u8, 4].into());
    }

    #[test]
    fn get_returns_element_at_valid_index() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When
        let elem = data.get(1);
        // Then
        assert_eq!(elem, Some(&2u8));
    }

    #[test]
    fn get_returns_none_for_out_of_bounds_index() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When
        let elem = data.get(3);
        // Then
        assert_eq!(elem, None);
    }

    #[test]
    fn try_mapped_succeeds_when_all_elements_succeed() {
        // Given
        let data: BoundedVec<u8, 2, 8> = [1u8, 2].into();
        // When
        let result = data.try_mapped(|x| 100u8.checked_div(x).ok_or("error"));
        // Then
        assert_eq!(result, Ok([100u8, 50].into()));
    }

    #[test]
    fn try_mapped_fails_when_any_element_fails() {
        // Given
        let data: BoundedVec<u8, 2, 8> = [0u8, 2].into();
        // When
        let result = data.try_mapped(|x| 100u8.checked_div(x).ok_or("error"));
        // Then
        assert_eq!(result, Err("error"));
    }

    #[test]
    fn try_mapped_ref_succeeds_when_all_elements_succeed() {
        // Given
        let data: BoundedVec<u8, 2, 8> = [1u8, 2].into();
        // When
        let result = data.try_mapped_ref(|x| 100u8.checked_div(*x).ok_or("error"));
        // Then
        assert_eq!(result, Ok([100u8, 50].into()));
    }

    #[test]
    fn try_mapped_ref_fails_when_any_element_fails() {
        // Given
        let data: BoundedVec<u8, 2, 8> = [0u8, 2].into();
        // When
        let result = data.try_mapped_ref(|x| 100u8.checked_div(*x).ok_or("error"));
        // Then
        assert_eq!(result, Err("error"));
    }

    #[test]
    fn split_last_returns_last_and_rest() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When
        let (last, rest) = data.split_last();
        // Then
        assert_eq!(last, &2u8);
        assert_eq!(rest, &[1u8]);
    }

    #[test]
    fn split_last_on_single_element_returns_empty_rest() {
        // Given
        let data: BoundedVec<_, 1, 8> = vec![1u8].try_into().unwrap();
        // When
        let (last, rest) = data.split_last();
        // Then
        assert_eq!(last, &1u8);
        assert!(rest.is_empty());
    }

    #[test]
    fn enumerated_pairs_elements_with_indices() {
        // Given
        let data: BoundedVec<_, 2, 8> = vec![1u8, 2].try_into().unwrap();
        // When
        let result = data.enumerated();
        // Then
        let expected: BoundedVec<_, 2, 8> = vec![(0, 1u8), (1, 2)].try_into().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn into_iter_yields_owned_elements() {
        // Given
        let vec = vec![1u8, 2];
        let data: BoundedVec<_, 2, 8> = vec.clone().try_into().unwrap();
        // When
        let collected: Vec<u8> = data.into_iter().collect();
        // Then
        assert_eq!(collected, vec);
    }

    #[test]
    fn iter_yields_references() {
        // Given
        let vec = vec![1u8, 2];
        let data: BoundedVec<_, 2, 8> = vec.clone().try_into().unwrap();
        // When
        let collected: Vec<&u8> = data.iter().collect();
        // Then
        assert_eq!(collected, vec.iter().collect::<Vec<&u8>>());
    }

    #[test]
    fn iter_mut_yields_mutable_references() {
        // Given
        let mut vec = vec![1u8, 2];
        let mut data: BoundedVec<_, 2, 8> = vec.clone().try_into().unwrap();
        // When
        let collected: Vec<&mut u8> = data.iter_mut().collect();
        // Then
        assert_eq!(collected, vec.iter_mut().collect::<Vec<&mut u8>>());
    }
}

#[cfg(test)]
mod serde_tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn deserialize_non_empty_vec_succeeds() {
        // Given
        let json = "[1, 2]";
        // When
        let result = serde_json::from_str::<BoundedVec<u8, 2, 3>>(json).unwrap();
        // Then
        assert_eq!(result.as_slice(), &[1, 2]);
    }

    #[test]
    fn deserialize_non_empty_vec_rejects_empty_array() {
        // Given
        let json = "[]";
        // When
        let result = serde_json::from_str::<BoundedVec<u8, 2, 3>>(json);
        // Then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn deserialize_empty_bounded_vec_accepts_empty_array() {
        // Given
        let json = "[]";
        // When
        let result = serde_json::from_str::<EmptyBoundedVec<u8, 3>>(json);
        // Then
        assert_matches!(result, Ok(_));
    }
}

#[cfg(test)]
mod hex_serde_tests {
    use assert_matches::assert_matches;

    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Wrapper {
        #[serde(with = "hex_serde")]
        data: BoundedVec<u8, 2, 4>,
    }

    #[test]
    fn roundtrip() {
        let original = Wrapper {
            data: vec![0xAB, 0xCD, 0xEF].try_into().unwrap(),
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"data":"abcdef"}"#);
        let deserialized: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    fn rejects_invalid_hex() {
        let json = r#"{"data":"zzzz"}"#;
        assert_matches!(serde_json::from_str::<Wrapper>(json), Err(_));
    }

    #[test]
    fn rejects_out_of_bounds() {
        // 1 byte is below lower bound of 2
        let json = r#"{"data":"ab"}"#;
        assert_matches!(serde_json::from_str::<Wrapper>(json), Err(_));

        // 5 bytes exceeds upper bound of 4
        let json = r#"{"data":"abcdef0102"}"#;
        assert_matches!(serde_json::from_str::<Wrapper>(json), Err(_));
    }
}

#[cfg(test)]
mod borsh_tests {
    use super::*;
    use borsh::BorshDeserialize;

    #[test]
    fn borsh_roundtrip_preserves_non_empty_vec() {
        // Given
        let original: BoundedVec<u8, 2, 4> = vec![1u8, 2, 3].try_into().unwrap();
        // When
        let bytes = borsh::to_vec(&original).unwrap();
        let deserialized: BoundedVec<u8, 2, 4> = BorshDeserialize::try_from_slice(&bytes).unwrap();
        // Then
        assert_eq!(deserialized, original);
    }

    #[test]
    fn borsh_roundtrip_preserves_empty_bounded_vec() {
        // Given
        let original: EmptyBoundedVec<u8, 4> = vec![1u8, 2].try_into().unwrap();
        // When
        let bytes = borsh::to_vec(&original).unwrap();
        let deserialized: EmptyBoundedVec<u8, 4> =
            BorshDeserialize::try_from_slice(&bytes).unwrap();
        // Then
        assert_eq!(deserialized, original);
    }

    #[test]
    fn borsh_deserialize_rejects_too_few_elements() {
        // Given
        let empty_bytes = borsh::to_vec(&Vec::<u8>::new()).unwrap();
        // When
        let result: Result<BoundedVec<u8, 2, 4>, _> =
            BorshDeserialize::try_from_slice(&empty_bytes);
        // Then
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn borsh_deserialize_rejects_too_many_elements() {
        // Given
        let too_many_bytes = borsh::to_vec(&vec![1u8, 2, 3, 4, 5]).unwrap();
        // When
        let result: Result<BoundedVec<u8, 2, 4>, _> =
            BorshDeserialize::try_from_slice(&too_many_bytes);
        // Then
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn borsh_deserialize_empty_bounded_rejects_too_many() {
        // Given
        let too_many_bytes = borsh::to_vec(&vec![1u8, 2, 3]).unwrap();
        // When
        let result: Result<EmptyBoundedVec<u8, 2>, _> =
            BorshDeserialize::try_from_slice(&too_many_bytes);
        // Then
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn borsh_deserialize_empty_bounded_accepts_empty() {
        // Given
        let empty_bytes = borsh::to_vec(&Vec::<u8>::new()).unwrap();
        // When
        let result: EmptyBoundedVec<u8, 4> =
            BorshDeserialize::try_from_slice(&empty_bytes).unwrap();
        // Then
        assert!(result.is_empty());
    }
}

#[cfg(all(test, feature = "abi"))]
mod borsh_schema_tests {
    use super::*;
    use borsh::{
        BorshSchema,
        schema::{BorshSchemaContainer, Definition},
    };

    #[test]
    fn schema_declaration_includes_bounds() {
        // Given / When
        let decl = BoundedVec::<u8, 2, 8>::declaration();
        // Then
        assert_eq!(decl, "BoundedVec<u8, 2, 8>");
    }

    #[test]
    fn schema_declaration_empty_bounded_starts_at_zero() {
        // Given / When
        let decl = EmptyBoundedVec::<u8, 4>::declaration();
        // Then
        assert_eq!(decl, "BoundedVec<u8, 0, 4>");
    }

    #[test]
    fn schema_encodes_length_range() {
        // Given
        let schema = BorshSchemaContainer::for_type::<BoundedVec<u8, 2, 8>>();
        // When
        let def = schema.get_definition("BoundedVec<u8, 2, 8>").unwrap();
        // Then
        match def {
            Definition::Sequence {
                length_width,
                length_range,
                elements,
            } => {
                assert_eq!(*length_width, Definition::DEFAULT_LENGTH_WIDTH);
                assert_eq!(*length_range, 2..=8);
                assert_eq!(elements, "u8");
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn schema_empty_bounded_range_starts_at_zero() {
        // Given
        let schema = BorshSchemaContainer::for_type::<EmptyBoundedVec<u8, 4>>();
        // When
        let def = schema.get_definition("BoundedVec<u8, 0, 4>").unwrap();
        // Then
        match def {
            Definition::Sequence { length_range, .. } => {
                assert_eq!(*length_range, 0..=4);
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn schema_validates_successfully() {
        // Given
        let schema = BorshSchemaContainer::for_type::<BoundedVec<u8, 2, 8>>();
        // When / Then
        assert_eq!(Ok(()), schema.validate());
    }
}
