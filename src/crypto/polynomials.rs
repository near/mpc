use frost_core::{
    keys::CoefficientCommitment, serialization::SerializableScalar, Field, Group, Scalar,
};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::ciphersuite::Ciphersuite;
use crate::protocol::{errors::ProtocolError, Participant};

use serde::{Deserialize, Deserializer, Serialize};

/// Polynomial structure of non-empty or non-zero coefficiants
/// Represents a polynomial with coefficients in the scalar field of the curve.
pub struct Polynomial<C: Ciphersuite> {
    /// The coefficients of our polynomial,
    /// The 0 term being the constant term of the polynomial
    coefficients: Vec<Scalar<C>>,
}

impl<C: Ciphersuite> Polynomial<C> {
    /// Constructs the polynomial out of scalars
    /// The first scalar (coefficients[0]) is the constant term
    /// The highest degree null coefficients are dropped
    pub fn new(coefficients: Vec<Scalar<C>>) -> Result<Self, ProtocolError> {
        if coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // count the number of zero coeffs before spotting the first non-zero
        let count = coefficients
            .iter()
            .rev()
            .take_while(|x| *x == &<C::Group as Group>::Field::zero())
            .count();
        if count == coefficients.len() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // get the degree + 1 of the polynomial
        let last_non_null = coefficients.len() - count;

        Ok(Polynomial {
            coefficients: coefficients[..last_non_null].to_vec(),
        })
    }

    /// Returns the coeficients of the polynomial
    pub fn get_coefficients(&self) -> Vec<Scalar<C>> {
        self.coefficients.to_vec()
    }

    /// Creates a random polynomial p of the given degree
    /// and sets p(0) = secret
    /// if the secret is not given then it is picked at random
    pub fn generate_polynomial(
        secret: Option<Scalar<C>>,
        degree: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, ProtocolError> {
        let poly_size = degree + 1;
        let mut coefficients = Vec::with_capacity(poly_size);
        // insert the secret share if exists
        let secret = secret.unwrap_or_else(|| <C::Group as Group>::Field::random(rng));

        coefficients.push(secret);
        for _ in 1..poly_size {
            coefficients.push(<C::Group as Group>::Field::random(rng));
        }
        // fails only if:
        // * polynomial is of degree 0 and the constant term is 0
        // * polynomial degree is the max of usize, and so degree + 1 is 0
        // such cases never happen in a classic (non-malicious) implementations
        Self::new(coefficients)
    }

    /// Returns the constant term or error in case the polynomial is empty
    pub fn eval_at_zero(&self) -> Result<SerializableScalar<C>, ProtocolError> {
        if self.coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        Ok(SerializableScalar(self.coefficients[0]))
    }

    /// Evaluates a polynomial at a certain scalar
    /// Evaluate the polynomial with the given coefficients
    /// at the point using Horner's method.
    /// Implements [`polynomial_evaluate`] from the spec:
    /// https://datatracker.ietf.org/doc/html/rfc9591#name-additional-polynomial-opera
    /// Returns error if the polynomial is empty
    pub fn eval_at_point(&self, point: Scalar<C>) -> Result<SerializableScalar<C>, ProtocolError> {
        if self.coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        if point == <C::Group as Group>::Field::zero() {
            self.eval_at_zero()
        } else {
            let mut value = <C::Group as Group>::Field::zero();
            for coeff in self.coefficients.iter().rev() {
                value = value * point + *coeff;
            }
            Ok(SerializableScalar(value))
        }
    }

    /// Evaluates a polynomial at the identifier of a participant
    pub fn eval_at_participant(
        &self,
        participant: Participant,
    ) -> Result<SerializableScalar<C>, ProtocolError> {
        let id = participant.scalar::<C>();
        self.eval_at_point(id)
    }

    /// Computes polynomial interpolation at a specific point
    /// using a sequence of sorted elements
    /// Input requirements:
    ///     * identifiers MUST be pairwise distinct and of length greater than 1
    ///     * shares and identifiers must be of same length
    ///     * identifier[i] corresponds to share[i]
    // Returns error if shares' and identifiers' lengths are distinct or less than or equals to 1
    pub fn eval_interpolation(
        identifiers: &[Scalar<C>],
        shares: &[SerializableScalar<C>],
        point: Option<&Scalar<C>>,
    ) -> Result<SerializableScalar<C>, ProtocolError>
    where
        Scalar<C>: ConstantTimeEq,
    {
        let mut interpolation = <C::Group as Group>::Field::zero();
        // raise Error if the lengths are not the same
        // or the number of identifiers (<= 1)
        if identifiers.len() != shares.len() || identifiers.len() <= 1 {
            return Err(ProtocolError::InvalidInterpolationArguments);
        }

        // Compute the Lagrange coefficients in batch
        let lagrange_coefficients = batch_compute_lagrange_coefficients::<C>(identifiers, point)?;

        // Compute y = f(point) via polynomial interpolation of these points of f
        for (lagrange_coefficient, share) in lagrange_coefficients.iter().zip(shares) {
            interpolation = interpolation + (lagrange_coefficient.0 * share.0);
        }

        Ok(SerializableScalar(interpolation))
    }

    /// Commits to a polynomial returning a sequence of group coefficients
    /// Creates a commitment vector of coefficients * G
    pub fn commit_polynomial(&self) -> Result<PolynomialCommitment<C>, ProtocolError> {
        // Computes the multiplication of every coefficient of p with the generator G
        let coef_commitment = self
            .coefficients
            .iter()
            .map(|c| CoefficientCommitment::new(C::Group::generator() * *c))
            .collect();
        // self cannot be the zero polynomial because there is no way
        // to create such a polynomial using this library. This implies the panic never occurs.
        PolynomialCommitment::new(coef_commitment)
    }

    /// Set the constant value of this polynomial to a new scalar
    /// Abort if the output polynomial is zero or empty
    pub fn set_nonzero_constant(&mut self, v: Scalar<C>) -> Result<(), ProtocolError> {
        if self.coefficients.is_empty()
            || (self.coefficients.len() == 1 && v == <C::Group as Group>::Field::zero())
        {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        self.coefficients[0] = v;
        Ok(())
    }

    /// Extends the Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_zero(&self) -> Result<Self, ProtocolError> {
        let mut coeffcommitment = vec![<C::Group as Group>::Field::zero()];
        coeffcommitment.extend(self.get_coefficients());
        Polynomial::new(coeffcommitment)
    }
}

/******************* Polynomial Commitment *******************/
/// Contains the commited coefficients of a polynomial i.e. coeff * G
#[derive(Clone)]
pub struct PolynomialCommitment<C: Ciphersuite> {
    /// The committed coefficients which are group elements
    /// (elliptic curve points)
    coefficients: Vec<CoefficientCommitment<C>>,
}

impl<C: Ciphersuite> PolynomialCommitment<C> {
    /// Creates a PolynomialCommitment out of a vector of CoefficientCommitment
    /// This function raises Error if the vector is empty or if it is the all identity vector
    pub fn new(coefcommitments: Vec<CoefficientCommitment<C>>) -> Result<Self, ProtocolError> {
        if coefcommitments.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // count the number of zero coeffs before spotting the first non-zero
        let count = coefcommitments
            .iter()
            .rev()
            .take_while(|x| x.value() == C::Group::identity())
            .count();
        if count == coefcommitments.len() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // get the number of non-identity coeffs
        let last_non_id = coefcommitments.len() - count;
        Ok(PolynomialCommitment {
            coefficients: coefcommitments[..last_non_id].to_vec(),
        })
    }

    /// Returns the coefficients of the
    pub fn get_coefficients(&self) -> Vec<CoefficientCommitment<C>> {
        self.coefficients.to_vec()
    }

    /// Outputs the degree of the commited polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Adds two PolynomialCommitment together
    /// and raises an error if the result is the identity
    pub fn add(&self, rhs: &Self) -> Result<Self, ProtocolError> {
        let max_len = self.coefficients.len().max(rhs.coefficients.len());
        let mut coefficients: Vec<CoefficientCommitment<C>> = Vec::with_capacity(max_len);

        // add polynomials even if they have different lengths
        for i in 0..max_len {
            let a = self.coefficients.get(i);
            let b = rhs.coefficients.get(i);

            let sum = match (a, b) {
                (Some(a), Some(b)) => CoefficientCommitment::new(a.value() + b.value()),
                (Some(a), None) => *a,
                (None, Some(b)) => *b,
                (None, None) =>
                // should be unreachable
                {
                    return Err(ProtocolError::EmptyOrZeroCoefficients)
                }
            };
            coefficients.push(sum);
        }

        // raises error in the case that the two polynomials are opposite
        PolynomialCommitment::new(coefficients)
    }

    /// Evaluates the commited polynomial on zero (outputs the constant term)
    /// Returns error if the polynomial is empty
    pub fn eval_at_zero(&self) -> Result<CoefficientCommitment<C>, ProtocolError> {
        if self.coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        Ok(self.coefficients[0])
    }

    /// Evaluates the commited polynomial at a specific value
    pub fn eval_at_point(
        &self,
        point: Scalar<C>,
    ) -> Result<CoefficientCommitment<C>, ProtocolError> {
        if self.coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        let mut out = C::Group::identity();
        for c in self.coefficients.iter().rev() {
            out = out * point + c.value();
        }
        Ok(CoefficientCommitment::new(out))
    }

    /// Evaluates the commited polynomial at a participant identifier.
    pub fn eval_at_participant(
        &self,
        participant: Participant,
    ) -> Result<CoefficientCommitment<C>, ProtocolError> {
        let id = participant.scalar::<C>();
        self.eval_at_point(id)
    }

    /// Computes polynomial interpolation on the exponent at a specific point
    /// using a sequence of sorted coefficient commitments
    /// Input requirements:
    ///     * identifiers MUST be pairwise distinct and of length greater than 1
    ///     * shares and identifiers must be of same length
    ///     * identifier[i] corresponds to share[i]
    // Returns error if shares' and identifiers' lengths are distinct or less than or equals to 1
    pub fn eval_exponent_interpolation(
        identifiers: &[Scalar<C>],
        shares: &[CoefficientCommitment<C>],
        point: Option<&Scalar<C>>,
    ) -> Result<CoefficientCommitment<C>, ProtocolError>
    where
        Scalar<C>: ConstantTimeEq,
    {
        let mut interpolation = C::Group::identity();
        // raise Error if the lengths are not the same
        // or the number of identifiers (<= 1)
        if identifiers.len() != shares.len() || identifiers.len() <= 1 {
            return Err(ProtocolError::InvalidInterpolationArguments);
        };

        // Compute the Lagrange coefficients in batch
        let lagrange_coefficients = batch_compute_lagrange_coefficients::<C>(identifiers, point)?;

        // Compute y = g^f(point) via polynomial interpolation of these points of f
        for (lagrange_coefficient, share) in lagrange_coefficients.iter().zip(shares) {
            interpolation = interpolation + (share.value() * lagrange_coefficient.0);
        }

        Ok(CoefficientCommitment::new(interpolation))
    }

    /// Extends the Commited Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_identity(&self) -> Result<Self, ProtocolError> {
        let mut coeffcommitment = vec![CoefficientCommitment::<C>::new(C::Group::identity())];
        coeffcommitment.extend(self.get_coefficients());
        PolynomialCommitment::new(coeffcommitment)
    }

    /// Set the constant value of this polynomial to a new group element
    /// Aborts if the output polynomial is the identity or empty
    pub fn set_non_identity_constant(
        &mut self,
        v: CoefficientCommitment<C>,
    ) -> Result<(), ProtocolError> {
        if self.coefficients.is_empty()
            || (self.coefficients.len() == 1 && v.value() == C::Group::identity())
        {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        self.coefficients[0] = v;

        Ok(())
    }
}

impl<C: Ciphersuite> Serialize for PolynomialCommitment<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.coefficients.serialize(serializer)
    }
}

// Deserialization enforcing non-empty vecs and non all-identity PolynomialCommitments
impl<'de, C: Ciphersuite> Deserialize<'de> for PolynomialCommitment<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let coefficients = Vec::<CoefficientCommitment<C>>::deserialize(deserializer)?;
        if coefficients.is_empty() {
            Err(serde::de::Error::custom("Polynomial must not be empty"))
        } else {
            // counts the number of successive identity elements on the highest
            // degree coefficients and aborts if the committed polynomial is the identity
            let is_identity = coefficients
                .iter()
                .rev()
                .all(|x| x.value() == C::Group::identity());
            if is_identity {
                return Err(serde::de::Error::custom(
                    "Polynomial must not be the identity",
                ));
            }
            Ok(PolynomialCommitment { coefficients })
        }
    }
}

/// Computes the Lagrange coefficient (a.k.a. Lagrange basis polynomial)
/// evaluated at point x.
/// lambda_i(x) = \prod_j (x - x_j)/(x_i - x_j)  where j != i
/// Note: if `x` is None then consider it as 0.
/// Note: `x_j` are elements in `point_set`
/// Note: if `x_i` is not in `point_set` then return an error
/// Warning: For correctness, this function assumes `point_set` does not have repeated values
/// We dont actually enforce this for performance reasons
pub fn compute_lagrange_coefficient<C: Ciphersuite>(
    points_set: &[Scalar<C>],
    x_i: &Scalar<C>,
    x: Option<&Scalar<C>>,
) -> Result<SerializableScalar<C>, ProtocolError> {
    let mut num = <C::Group as Group>::Field::one();
    let mut den = <C::Group as Group>::Field::one();

    if points_set.len() <= 1 {
        // returns error if there is not enough points to interpolate
        return Err(ProtocolError::InvalidInterpolationArguments);
    }

    let mut contains_i = false;
    if let Some(x) = x {
        for x_j in points_set.iter() {
            if *x_i == *x_j {
                contains_i = true;
                continue;
            }
            num = num * (*x - *x_j);
            den = den * (*x_i - *x_j);
        }
    } else {
        for x_j in points_set.iter() {
            if *x_i == *x_j {
                contains_i = true;
                continue;
            }
            // Both signs inverted just to avoid requiring an extra negation
            num = num * *x_j;
            den = den * (*x_j - *x_i);
        }
    }

    // if i is not in the set of points
    if !contains_i {
        return Err(ProtocolError::InvalidInterpolationArguments);
    }

    // denominator will never be 0 here, therefore it is safe to invert
    let den = <C::Group as Group>::Field::invert(&den).map_err(|_| ProtocolError::Unreachable)?;
    Ok(SerializableScalar(num * den))
}

/// Computes all Lagrange basis coefficients lambda_i(x) for the nodes in `points_set`,
/// evaluated at a single point `x`, using batch operations to reduce field inversions.
///
/// Lagrange coefficient definition:
///   lambda_i(x) = \prod_{j!=i} (x - x_j) / (x_i - x_j)
///
/// Inputs:
/// - `points_set` = {x_0, x_1, …}. Each lambda_i corresponds to x_i ∈ `points_set`.
/// - `x`: the evaluation point. If `None`, it is treated as 0.
///
/// Requirements:
/// - `points_set.len() > 1`.
/// - All x_i are distinct.
///
/// Early exit:
/// - If x equals some x_k in `points_set`, return the Kronecker delta vector:
///   lambda_k(x)=1 and lambda_i(x)=0 for i!=k.
///
/// Batch computation strategy:
/// 1) Denominators: for each i, compute d_i = \prod_{j!=i} (x_i - x_j),
///    then invert all d_i together in a single batch. This reduces n separate
///    inversions to 1 batch inversion (O(n) instead of O(n^2)).
/// 2) Numerators: compute the global numerator N = \prod_j (x - x_j),
///    then for each i obtain n_i = N / (x - x_i) using batch inversion of (x - x_i).
/// 3) Combine: lambda_i(x) = n_i * (d_i^-1).
///
/// Returns:
/// - Vec<SerializableScalar<C>>: Lagrange coefficients corresponding to each x_i.
///
/// Example (over reals for clarity):
/// - points_set = [1, 2, 4], x = 3:
///   lambda(3) = [-1/3, 1, 1/3]   // sums to 1
/// - points_set = [1, 2, 4], x = 2:
///   lambda(2) = [0, 1, 0]        // x equals x₁
/// - points_set = [1, 3, 4], x = None (so x=0):
///   lambda(0) = [2, -2, 1]       // sums to 1
pub fn batch_compute_lagrange_coefficients<C: Ciphersuite>(
    points_set: &[Scalar<C>],
    x: Option<&Scalar<C>>,
) -> Result<Vec<SerializableScalar<C>>, ProtocolError>
where
    Scalar<C>: ConstantTimeEq,
{
    let n = points_set.len();
    if n <= 1 {
        return Err(ProtocolError::InvalidInterpolationArguments);
    }

    // Treat None as zero
    let zero = <C::Group as Group>::Field::zero();
    let x = x.unwrap_or(&zero);

    // If x exactly equals some x_i, return Kronecker delta vector
    // This is done in constant time by iterating through all elements
    // and accumulating a Choice without short-circuiting.
    let mut kronecker_index = CtOption::new(0u32, Choice::from(0u8)); // Initialize as CtOption::none() effectively

    for (i, p) in points_set.iter().enumerate() {
        let is_equal = p.ct_eq(x);
        // If is_equal is true, select 'i', otherwise keep the current k_index_val
        kronecker_index = CtOption::conditional_select(
            &kronecker_index,
            &CtOption::new(i as u32, is_equal),
            is_equal,
        );
    }

    if kronecker_index.is_some().into() {
        let kronecker_index_value = kronecker_index.unwrap() as usize;
        let mut coeffs = vec![SerializableScalar(<C::Group as Group>::Field::zero()); n];
        coeffs[kronecker_index_value] = SerializableScalar(<C::Group as Group>::Field::one());
        return Ok(coeffs);
    }

    // Compute denominators d_i = \prod_{j!=i} (x_i - x_j) for each point x_i in points_set.
    // This corresponds to the denominator of the Lagrange basis polynomial lambda_i(x):
    //    lambda_i(x) = prod_{j!=i} (x - x_j) / (x_i - x_j)
    // By computing all d_i here, we can invert them in a single batch later, which
    // is much faster than inverting each individually.
    let mut denominators = Vec::with_capacity(n);
    for i in 0..n {
        let mut den = <C::Group as Group>::Field::one();
        for j in 0..n {
            if i == j {
                continue;
            }
            den = den * (points_set[i] - points_set[j]);
        }
        denominators.push(den);
    }

    // Invert all denominators in one batch for efficiency
    let inv_denominators = batch_invert::<C>(&denominators)?;

    // Special case: x = 0
    let (numerator_prod, inv_factors) = if *x == zero {
        // Compute P = \prod_j (-1)* *x_j
        let mut p = <C::Group as Group>::Field::one();
        for x_i in points_set.iter() {
            p = p * *x_i;
        }

        // For constant time computation always compute minus_p
        let minus_p = zero - p;

        // Batch invert points_set to get 1 / x_i
        let inv_xis = batch_invert::<C>(points_set)?;
        // Return the proper numerator based on the number of elements
        (if n % 2 == 0 { minus_p } else { p }, inv_xis)
    } else {
        // General case: x != 0
        let mut full_numerator = <C::Group as Group>::Field::one();
        let mut x_minus_xi_vec = Vec::with_capacity(n);
        for x_i in points_set.iter() {
            let x_minus_xi = *x - *x_i;
            full_numerator = full_numerator * x_minus_xi;
            x_minus_xi_vec.push(x_minus_xi);
        }
        let inv_x_minus_xi_vec = batch_invert::<C>(&x_minus_xi_vec)?;
        (full_numerator, inv_x_minus_xi_vec)
    };

    // Compute final Lagrange coefficients
    let mut lagrange_coeffs = Vec::with_capacity(n);
    for i in 0..n {
        // For each i, compute the numerator n_i = N / (x - x_i), where N = Prod_j (x - x_j).
        // This is done by multiplying the total product `numerator_prod` by the pre-computed
        // inverse of the term `(x - x_i)` (or `x_i` if x is zero).
        let num_i = numerator_prod * inv_factors[i];
        lagrange_coeffs.push(SerializableScalar(num_i * inv_denominators[i]));
    }

    Ok(lagrange_coeffs)
}

/// Batch inversion of a list of field elements.
/// Returns a vector of inverses in the same order.
/// Uses the standard prefix-product / suffix-product trick for O(n) inversions instead of O(n²).
pub fn batch_invert<C: Ciphersuite>(values: &[Scalar<C>]) -> Result<Vec<Scalar<C>>, ProtocolError> {
    if values.is_empty() {
        return Err(ProtocolError::InvalidInterpolationArguments);
    }

    let mut products: Vec<Scalar<C>> = Vec::with_capacity(values.len());
    let mut acc = <C::Group as Group>::Field::one();
    for v in values {
        acc = acc * *v;
        products.push(acc);
    }

    // Invert the total product
    let mut inv_last = <C::Group as Group>::Field::invert(&acc)
        .map_err(|_| ProtocolError::InvalidInterpolationArguments)?;

    // Compute individual inverses usin suffix products
    let mut inverted = vec![<C::Group as Group>::Field::one(); values.len()];
    for i in (1..values.len()).rev() {
        inverted[i] = products[i - 1] * inv_last;
        inv_last = inv_last * values[i];
    }
    inverted[0] = inv_last;

    Ok(inverted)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::{generate_participants, generate_participants_with_random_ids};
    use frost_core::Field;
    use frost_secp256k1::{Secp256K1Group, Secp256K1ScalarField, Secp256K1Sha256};
    use k256::Scalar;
    use rand_core::{OsRng, RngCore};
    type C = Secp256K1Sha256;

    #[test]
    fn abort_no_polynomial() {
        let poly = Polynomial::<C>::new(vec![]);
        assert!(poly.is_err(), "Polynomial should be raising error");

        let vec = vec![Secp256K1ScalarField::zero(); 10];
        let poly = Polynomial::<C>::new(vec);
        assert!(poly.is_err(), "Polynomial should be raising error");
    }

    #[test]
    fn abort_no_polynomial_commitments() {
        let poly = PolynomialCommitment::<C>::new(vec![]);
        assert!(poly.is_err(), "Polynomial should be raising error");
        let vec = vec![CoefficientCommitment::<C>::new(Secp256K1Group::identity()); 10];
        let poly = PolynomialCommitment::new(vec);
        assert!(poly.is_err(), "Polynomial should be raising error");
    }

    #[test]
    fn test_get_coefficients_poly() {
        let poly_size = 50;
        let mut coefficients = Vec::with_capacity(poly_size);

        for _ in 0..poly_size {
            coefficients
                .push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng));
        }

        let poly = Polynomial::<C>::new(coefficients.clone()).unwrap();
        for (a, b) in poly.get_coefficients().iter().zip(coefficients) {
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn test_get_coefficients_commitments() {
        let poly_size = 50;
        let mut coefficients = Vec::with_capacity(poly_size);

        let generator = <C as frost_core::Ciphersuite>::Group::generator();
        for _ in 0..poly_size {
            let scalar =
                <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
            coefficients.push(CoefficientCommitment::<C>::new(generator * scalar));
        }

        let poly = PolynomialCommitment::<C>::new(coefficients.clone()).unwrap();
        for (a, b) in poly.get_coefficients().iter().zip(coefficients) {
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn test_eval_on_zero_poly() {
        let poly_size = 20;
        let mut coefficients = Vec::with_capacity(poly_size);

        let zero_coeff =
            <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
        for i in 0..poly_size {
            if i == 0 {
                coefficients.push(zero_coeff);
            } else {
                coefficients.push(
                    <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng),
                );
            }
        }

        let poly = Polynomial::<C>::new(coefficients).unwrap();
        // test eval_at_zero
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert_eq!(zero_coeff, poly.eval_at_zero().unwrap().0);
        assert_eq!(zero_coeff, poly.eval_at_point(point).unwrap().0)
    }

    #[test]
    fn test_eval_on_zero_commitments() {
        let poly_size = 50;
        let mut coefficients = Vec::with_capacity(poly_size);

        let generator = <C as frost_core::Ciphersuite>::Group::generator();
        let zero_coeff =
            <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
        let zero_coeff = generator * zero_coeff;
        for i in 0..poly_size {
            if i == 0 {
                coefficients.push(CoefficientCommitment::<C>::new(zero_coeff));
            } else {
                let scalar =
                    <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
                coefficients.push(CoefficientCommitment::<C>::new(generator * scalar));
            }
        }

        let poly = PolynomialCommitment::<C>::new(coefficients).unwrap();
        // test eval_at_zero
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert_eq!(zero_coeff, poly.eval_at_zero().unwrap().value());
        assert_eq!(zero_coeff, poly.eval_at_point(point).unwrap().value())
    }

    #[test]
    fn test_eval_on_point() {
        let poly_size = 4;
        let mut coefficients = Vec::with_capacity(poly_size);
        let mut coefficients_com = Vec::with_capacity(poly_size);

        // X^3 + X^2 + X + 1
        for _ in 0..poly_size {
            coefficients.push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::one());
            coefficients_com.push(CoefficientCommitment::<C>::new(
                <<C as frost_core::Ciphersuite>::Group as Group>::generator(),
            ))
        }

        let poly = Polynomial::<C>::new(coefficients).unwrap();
        let polycom = PolynomialCommitment::<C>::new(coefficients_com).unwrap();

        for _ in 1..50 {
            // test eval_at_zero
            let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
            // explicit calculation
            let output_poly_eval = point * point * point
                + point * point
                + point
                + <<C as frost_core::Ciphersuite>::Group as Group>::Field::one();
            let output_polycom_eval =
                <C as frost_core::Ciphersuite>::Group::generator() * output_poly_eval;

            assert_eq!(output_poly_eval, poly.eval_at_point(point).unwrap().0);
            assert_eq!(
                output_polycom_eval,
                polycom.eval_at_point(point).unwrap().value()
            )
        }
    }

    #[test]
    fn test_eval_on_participant() {
        let poly_size = 6;
        let mut coefficients = Vec::with_capacity(poly_size);
        let mut coefficients_com = Vec::with_capacity(poly_size);

        // X^5 + X^3 + X
        for i in 0..poly_size {
            if i % 2 == 1 {
                coefficients.push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::one());
                coefficients_com.push(CoefficientCommitment::<C>::new(
                    <<C as frost_core::Ciphersuite>::Group as Group>::generator(),
                ))
            } else {
                coefficients.push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::zero());
                coefficients_com.push(CoefficientCommitment::<C>::new(
                    <<C as frost_core::Ciphersuite>::Group as Group>::identity(),
                ))
            }
        }

        let poly = Polynomial::<C>::new(coefficients).unwrap();
        let polycom = PolynomialCommitment::<C>::new(coefficients_com).unwrap();

        for _ in 1..50 {
            let participant = Participant::from(OsRng.next_u32());
            let point = participant.scalar::<C>();
            // explicit calculation
            let output_poly_eval =
                point * point * point * point * point + point * point * point + point;
            let output_polycom_eval =
                <C as frost_core::Ciphersuite>::Group::generator() * output_poly_eval;

            assert_eq!(
                output_poly_eval,
                poly.eval_at_participant(participant).unwrap().0
            );
            assert_eq!(
                output_polycom_eval,
                polycom.eval_at_participant(participant).unwrap().value()
            )
        }
    }

    #[test]
    fn test_commit_polynomial() {
        let poly_size = 4;
        let mut coefficients = Vec::with_capacity(poly_size);
        let mut coefficients_com = Vec::with_capacity(poly_size);
        for _ in 0..poly_size {
            let scalar =
                <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
            coefficients.push(scalar);
            let commitment = <<C as frost_core::Ciphersuite>::Group as Group>::generator() * scalar;
            coefficients_com.push(CoefficientCommitment::<C>::new(commitment));
        }
        let poly = Polynomial::<C>::new(coefficients).unwrap();
        let polycom = poly.commit_polynomial().unwrap();
        for (a, b) in polycom.get_coefficients().iter().zip(coefficients_com) {
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn test_generate_polynomial() {
        let degree = 10;
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
        let poly = Polynomial::<C>::generate_polynomial(Some(point), degree, &mut OsRng).unwrap();
        let coeffs = poly.get_coefficients();
        assert_eq!(coeffs.len(), degree + 1);
        assert_eq!(coeffs[0], point);
    }

    #[test]
    fn test_set_to_non_zero_poly() {
        let poly_size = 20;
        let mut coefficients = Vec::with_capacity(poly_size);

        let zero_coeff =
            <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
        for i in 0..poly_size {
            let mut rand_scalar =
                <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
            while i == 0 && zero_coeff == rand_scalar {
                rand_scalar =
                    <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut OsRng);
            }
            coefficients.push(rand_scalar);
        }

        let mut poly = Polynomial::<C>::new(coefficients).unwrap();
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert!(zero_coeff != poly.eval_at_zero().unwrap().0);
        assert!(zero_coeff != poly.eval_at_point(point).unwrap().0);

        poly.set_nonzero_constant(zero_coeff).unwrap();
        assert_eq!(zero_coeff, poly.eval_at_zero().unwrap().0);
        assert_eq!(zero_coeff, poly.eval_at_point(point).unwrap().0);

        let one = <<C as frost_core::Ciphersuite>::Group as Group>::Field::one();
        let mut poly_abort =
            Polynomial::<C>::generate_polynomial(Some(one), 0, &mut OsRng).unwrap();
        let zero = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert!(poly_abort.set_nonzero_constant(zero).is_err())
    }

    #[test]
    fn test_eval_interpolation() {
        let degree = 5;
        let participants = (0..degree + 1)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        let ids = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|_| SerializableScalar::<C>(Secp256K1ScalarField::random(&mut rand_core::OsRng)))
            .collect::<Vec<_>>();
        let ref_point = Some(Secp256K1ScalarField::random(&mut rand_core::OsRng));
        let point = ref_point.as_ref();
        assert!(Polynomial::eval_interpolation(&ids, &shares, point).is_ok());
        assert!(Polynomial::eval_interpolation(&ids, &shares, None).is_ok());
        assert!(Polynomial::eval_interpolation(&ids[..1], &shares[..1], None).is_err());
        assert!(Polynomial::eval_interpolation(&ids[..0], &shares[..0], None).is_err());
        assert!(Polynomial::eval_interpolation(&ids[..2], &shares, None).is_err());
    }

    #[test]
    fn poly_eval_interpolate() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        // evaluate polynomial on 6 different points
        let participants = generate_participants(degree + 1);

        let shares = participants
            .iter()
            .map(|p| poly.eval_at_participant(*p).unwrap())
            .collect::<Vec<_>>();

        // interpolate the polynomial using the shares at arbitrary points
        let scalars = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        for _ in 0..100 {
            // create arbitrary point
            let point = Secp256K1ScalarField::random(&mut OsRng);
            // interpolate on this point
            let interpolation = Polynomial::eval_interpolation(&scalars, &shares, Some(&point))
                .expect("Interpolation has the correct inputs");
            // evaluate the polynomial on the point
            let evaluation = poly.eval_at_point(point).unwrap();

            // verify that the interpolated points match the polynomial evaluation
            assert_eq!(interpolation.0, evaluation.0);
        }
    }

    #[test]
    fn test_eval_exponent_interpolation() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial().unwrap();

        let participants = (0..degree + 1)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|p| compoly.eval_at_participant(*p).unwrap())
            .collect::<Vec<_>>();

        let ids = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();

        let ref_point = Some(Secp256K1ScalarField::random(&mut rand_core::OsRng));
        let point = ref_point.as_ref();

        assert!(
            PolynomialCommitment::<C>::eval_exponent_interpolation(&ids, &shares, point).is_ok()
        );
        assert!(
            PolynomialCommitment::<C>::eval_exponent_interpolation(&ids, &shares, None).is_ok()
        );
        assert!(PolynomialCommitment::<C>::eval_exponent_interpolation(
            &ids[..1],
            &shares[..1],
            None
        )
        .is_err());
        assert!(PolynomialCommitment::<C>::eval_exponent_interpolation(
            &ids[..0],
            &shares[..0],
            None
        )
        .is_err());
        assert!(
            PolynomialCommitment::<C>::eval_exponent_interpolation(&ids[..2], &shares, None)
                .is_err()
        );
    }

    #[test]
    fn com_generate_evaluate_interpolate() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial().unwrap();
        // evaluate polynomial on 6 different points
        let participants = generate_participants(degree + 1);

        let shares = participants
            .iter()
            .map(|p| compoly.eval_at_participant(*p).unwrap())
            .collect::<Vec<_>>();

        // interpolate the polynomial using the shares at arbitrary points
        let scalars = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        for _ in 0..100 {
            // create arbitrary point
            let point = Secp256K1ScalarField::random(&mut OsRng);
            // interpolate on this point
            let interpolation = PolynomialCommitment::<C>::eval_exponent_interpolation(
                &scalars,
                &shares,
                Some(&point),
            )
            .expect("Interpolation has the correct inputs");
            // evaluate the polynomial on the point
            let evaluation = compoly.eval_at_point(point).unwrap();

            // verify that the interpolated points match the polynomial evaluation
            assert_eq!(interpolation.value(), evaluation.value());
        }
    }

    #[test]
    fn test_extend_with_identity() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial().unwrap();
        // evaluate polynomial on 6 different points

        let extended = compoly.extend_with_identity().unwrap().get_coefficients();
        let coeffs = compoly.get_coefficients();
        for i in 0..extended.len() {
            if i == 0 {
                assert_eq!(
                    extended[i].value(),
                    <C as frost_core::Ciphersuite>::Group::identity()
                )
            } else {
                assert_eq!(extended[i].value(), coeffs[i - 1].value());
            }
        }
    }

    #[test]
    fn add_polynomial_commitments() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial().unwrap();
        // add two polynomials of the same height
        let sum = compoly.add(&compoly).unwrap();

        let coefpoly = compoly.get_coefficients();
        let mut coefsum = sum.get_coefficients();

        assert_eq!(coefpoly.len(), coefsum.len());

        // I need the scalar 2
        // the easiest way to do so is to create a participant with identity 1
        // transforming the identity into scalar would add +1
        let two = Participant::from(1u32).scalar::<C>();
        for (c, two_c) in coefpoly.iter().zip(&coefsum) {
            assert_eq!(c.value() * two, two_c.value())
        }

        coefsum.extend(&coefsum.clone());
        let extend_sum_compoly =
            PolynomialCommitment::new(coefsum).expect("We have proper coefficients");
        // add two polynomials of different heights
        let ext_sum_left = extend_sum_compoly.add(&compoly).unwrap().get_coefficients();
        let ext_sum_right = compoly.add(&extend_sum_compoly).unwrap().get_coefficients();
        for (c_left, c_right) in ext_sum_left.iter().zip(ext_sum_right) {
            assert_eq!(c_left.value(), c_right.value());
        }

        let three = Participant::from(2u32).scalar::<C>();
        for i in 0..ext_sum_left.len() {
            let c = ext_sum_left[i].value();
            if i < ext_sum_left.len() / 2 {
                assert_eq!(c, coefpoly[i].value() * three);
            } else {
                let index = i - ext_sum_left.len() / 2;
                assert_eq!(c, coefpoly[index].value() * two);
            }
        }
    }

    #[test]
    fn test_batch_edge_cases_errors() {
        let points = vec![
            Participant::from(1u32).scalar::<C>(),
            Participant::from(1u32).scalar::<C>(), // duplicate
        ];
        let result =
            batch_compute_lagrange_coefficients::<C>(&points, Some(&Secp256K1ScalarField::zero()));
        assert!(result.is_err());

        let points_single = vec![Participant::from(1u32).scalar::<C>()];
        let result = batch_compute_lagrange_coefficients::<C>(
            &points_single,
            Some(&Secp256K1ScalarField::zero()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_lagrange_coefficient_cubic_polynomial() {
        let points = generate_participants_with_random_ids(5, &mut OsRng)
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        let mut result = Secp256K1ScalarField::zero();
        let target_point = Scalar::generate_biased(&mut OsRng);
        for point in points.iter() {
            let coefficient =
                compute_lagrange_coefficient::<C>(&points, point, Some(&target_point))
                    .unwrap()
                    .0;
            result += coefficient * point * point * point;
        }
        assert_eq!(result, target_point * target_point * target_point);
    }

    #[test]
    fn test_compute_lagrange_coefficient_edge_cases() {
        let one = Scalar::ONE;
        let zero = Scalar::ZERO;
        let target_point = Scalar::generate_biased(&mut OsRng);

        // coefficients computed manually
        assert_eq!(
            compute_lagrange_coefficient::<C>(&[one, zero], &one, Some(&target_point))
                .unwrap()
                .0,
            target_point
        );
        assert_eq!(
            compute_lagrange_coefficient::<C>(&[one, zero], &zero, Some(&target_point))
                .unwrap()
                .0,
            (one - target_point)
        );

        // target point is None should be treated as 0
        let random_point1 = Scalar::generate_biased(&mut OsRng);
        let random_point2 = Scalar::generate_biased(&mut OsRng);
        assert_eq!(
            compute_lagrange_coefficient::<C>(
                &[random_point1, random_point2],
                &random_point1,
                Some(&zero)
            )
            .unwrap()
            .0,
            compute_lagrange_coefficient::<C>(
                &[random_point1, random_point2],
                &random_point1,
                None
            )
            .unwrap()
            .0
        );

        // point not in set
        assert!(
            compute_lagrange_coefficient::<C>(&[one, zero], &(one + one), Some(&target_point))
                .is_err()
        );

        // not enough points
        assert!(compute_lagrange_coefficient::<C>(&[one], &one, Some(&target_point)).is_err());
    }

    #[test]
    fn test_lagrange_computation_equivalence() {
        let degree = 10;
        let participants = generate_participants(degree + 1);

        let ids = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        let point = Some(Secp256K1ScalarField::random(&mut rand_core::OsRng));

        // Sequential
        let mut lagrange_coefficients_seq = Vec::new();
        for id in &ids {
            lagrange_coefficients_seq
                .push(compute_lagrange_coefficient::<C>(&ids, id, point.as_ref()).unwrap());
        }

        // Batch
        let lagrange_coefficients_batch =
            batch_compute_lagrange_coefficients::<C>(&ids, point.as_ref()).unwrap();

        // Verify results match
        for (a, b) in lagrange_coefficients_seq
            .iter()
            .zip(lagrange_coefficients_batch.iter())
        {
            assert_eq!(a.0, b.0);
        }
    }

    #[test]
    fn test_batch_compute_lagrange_coefficients_early_exit() {
        use frost_core::Field;
        use k256::Scalar;
        use std::ops::Neg;
        let points_set = [Scalar::from(1u32), Scalar::from(2u32), Scalar::from(3u32)];
        let x_equals_point = Scalar::from(2u32); // x is equal to points_set[1]

        let coeffs =
            batch_compute_lagrange_coefficients::<C>(&points_set[..], Some(&x_equals_point))
                .unwrap();

        // Expect Kronecker delta vector: [0, 1, 0]
        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0].0, Secp256K1ScalarField::zero());
        assert_eq!(coeffs[1].0, Secp256K1ScalarField::one());
        assert_eq!(coeffs[2].0, Secp256K1ScalarField::zero());

        let x_not_equals_point = Scalar::from(4u32); // x is not equal to any point
        let coeffs_no_early_exit =
            batch_compute_lagrange_coefficients::<C>(&points_set[..], Some(&x_not_equals_point))
                .unwrap();
        // Verify the calculated Lagrange coefficients
        assert_eq!(coeffs_no_early_exit.len(), 3);
        assert_eq!(coeffs_no_early_exit[0].0, Scalar::from(1u32)); // lambda_0(4) = 1
        assert_eq!(coeffs_no_early_exit[1].0, Scalar::from(3u32).neg()); // lambda_1(4) = -3
        assert_eq!(coeffs_no_early_exit[2].0, Scalar::from(3u32)); // lambda_2(4) = 3
    }

    #[test]
    fn test_eval_exponent_interpolation_against_interpolation_times_g_at_none(
    ) -> Result<(), ProtocolError> {
        for participants in 2..20 {
            for degree in 1..participants {
                let participants = generate_participants(participants);

                let ids = participants
                    .iter()
                    .map(|p| p.scalar::<C>())
                    .collect::<Vec<_>>();

                // generate polynomial
                let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
                    .expect("Generation must not fail with overwhealming probability");

                // build all the shares
                let shares = participants
                    .iter()
                    .map(|p| poly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                let compoly = poly.commit_polynomial().unwrap();

                // build all commited shares
                let com_shares = participants
                    .iter()
                    .map(|p| compoly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                // use only degree + 1 shares to evaluate exponent
                let exponent_eval = PolynomialCommitment::eval_exponent_interpolation(
                    &ids[..degree + 1],
                    &com_shares[..degree + 1],
                    None,
                )?;

                // use all to evaluate the share
                let eval = Polynomial::eval_interpolation(&ids, &shares, None)?;

                println!("{participants:?} {degree:?}");
                assert_eq!(
                    exponent_eval.value(),
                    <C as frost_core::Ciphersuite>::Group::generator() * eval.0
                );
            }
        }

        Ok(())
    }
    #[test]
    fn test_eval_exponent_interpolation_against_interpolation_times_g_at_some(
    ) -> Result<(), ProtocolError> {
        for participants in 2..20 {
            for degree in 1..participants {
                let participants = generate_participants(participants);

                let ids = participants
                    .iter()
                    .map(|p| p.scalar::<C>())
                    .collect::<Vec<_>>();

                // generate polynomial
                let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
                    .expect("Generation must not fail with overwhealming probability");

                // build all the shares
                let shares = participants
                    .iter()
                    .map(|p| poly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                let compoly = poly.commit_polynomial().unwrap();

                // build all commited shares
                let com_shares = participants
                    .iter()
                    .map(|p| compoly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                let point = Some(Secp256K1ScalarField::random(&mut rand_core::OsRng));

                // use only degree + 1 shares to evaluate exponent
                let exponent_eval = PolynomialCommitment::eval_exponent_interpolation(
                    &ids[..degree + 1],
                    &com_shares[..degree + 1],
                    point.as_ref(),
                )?;

                // use all to evaluate the share
                let eval = Polynomial::eval_interpolation(&ids, &shares, point.as_ref())?;

                assert_eq!(
                    exponent_eval.value(),
                    <C as frost_core::Ciphersuite>::Group::generator() * eval.0
                );
            }
        }

        Ok(())
    }
}
