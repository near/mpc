use frost_core::{
    keys::CoefficientCommitment, serialization::SerializableScalar, Field, Group, Scalar,
};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use crate::crypto::ciphersuite::Ciphersuite;
use crate::errors::ProtocolError;
use crate::participants::Participant;

use super::{batch_compute_lagrange_coefficients, PolynomialCommitment};

/// Polynomial structure of non-empty or non-zero coefficients
/// Represents a polynomial with coefficients in the scalar field of the curve.
///  TODO(#2582): Derive `ZeroizeOnDrop` for `Polynomial` structure in threshold-signatures
pub struct Polynomial<C: Ciphersuite> {
    /// The coefficients of our polynomial,
    /// The 0 term being the constant term of the polynomial
    coefficients: Vec<Scalar<C>>,
}

impl<C: Ciphersuite> Polynomial<C> {
    /// Constructs the polynomial out of scalars
    /// The first scalar (coefficients[0]) is the constant term
    /// The highest degree null coefficients are dropped
    pub fn new(coefficients: &[Scalar<C>]) -> Result<Self, ProtocolError> {
        if coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // count the number of zero coeffs before spotting the first non-zero
        let count = coefficients
            .iter()
            .rev()
            .take_while(|x| *x == &<C::Group as Group>::Field::zero())
            .count();

        // get the degree + 1 of the polynomial
        let last_non_null = coefficients.len() - count;

        let new_coefficients = coefficients
            .get(..last_non_null)
            .ok_or(ProtocolError::EmptyOrZeroCoefficients)?
            .to_vec();
        if new_coefficients.is_empty() {
            Err(ProtocolError::EmptyOrZeroCoefficients)
        } else {
            Ok(Self {
                coefficients: new_coefficients,
            })
        }
    }

    /// Returns the coefficients of the polynomial
    pub fn get_coefficients(&self) -> Vec<Scalar<C>> {
        self.coefficients.clone()
    }

    /// Creates a random polynomial p of the given degree
    /// and sets p(0) = secret
    /// if the secret is not given then it is picked at random
    pub fn generate_polynomial(
        secret: Option<Scalar<C>>,
        degree: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, ProtocolError> {
        let poly_size = degree
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow)?;

        let poly_alloc_size = poly_size
            .checked_mul(Self::coefficient_size())
            .ok_or(ProtocolError::IntegerOverflow)?;
        // @dev why not usize::MAX? https://github.com/near/threshold-signatures/pull/163#discussion_r2447505305
        // Allocations must fit within isize range.
        if poly_alloc_size > isize::MAX as usize {
            return Err(ProtocolError::IntegerOverflow);
        }

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
        Self::new(&coefficients)
    }

    /// Returns the constant term or error in case the polynomial is empty
    pub fn eval_at_zero(&self) -> Result<SerializableScalar<C>, ProtocolError> {
        let result = self
            .coefficients
            .first()
            .copied()
            .ok_or(ProtocolError::EmptyOrZeroCoefficients)?;
        Ok(SerializableScalar(result))
    }

    /// Evaluates a polynomial at a certain scalar
    /// Evaluate the polynomial with the given coefficients
    /// at the point using Horner's method.
    /// Implements [`polynomial_evaluate`] from the spec:
    /// <https://datatracker.ietf.org/doc/html/rfc9591#name-additional-polynomial-opera>
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
            .collect::<Vec<_>>();
        // self cannot be the zero polynomial because there is no way
        // to create such a polynomial using this library. This implies the panic never occurs.
        PolynomialCommitment::new(&coef_commitment)
    }

    /// Set the constant value of this polynomial to a new scalar
    /// Abort if the output polynomial would be zero or empty
    pub fn set_nonzero_constant(&mut self, v: Scalar<C>) -> Result<(), ProtocolError> {
        let coefficients_len = self.coefficients.len();
        self.coefficients
            .first_mut()
            .map_or(Err(ProtocolError::EmptyOrZeroCoefficients), |first| {
                if v == <C::Group as Group>::Field::zero() && coefficients_len == 1 {
                    Err(ProtocolError::EmptyOrZeroCoefficients)
                } else {
                    *first = v;
                    Ok(())
                }
            })
    }

    /// Extends the Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_zero(&self) -> Result<Self, ProtocolError> {
        let mut coeffcommitment = vec![<C::Group as Group>::Field::zero()];
        coeffcommitment.extend(self.get_coefficients());
        Self::new(&coeffcommitment)
    }

    fn coefficient_size() -> usize {
        core::mem::size_of::<<<C::Group as Group>::Field as Field>::Scalar>()
    }
}
