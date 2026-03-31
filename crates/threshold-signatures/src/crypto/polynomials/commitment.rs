use frost_core::{keys::CoefficientCommitment, Group, Scalar};
use subtle::ConstantTimeEq;

use crate::crypto::ciphersuite::Ciphersuite;
use crate::errors::ProtocolError;
use crate::participants::Participant;

use serde::{Deserialize, Deserializer, Serialize};

use super::batch_compute_lagrange_coefficients;

/// Contains the committed coefficients of a polynomial i.e. coeff * G
#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialCommitment<C: Ciphersuite> {
    /// The committed coefficients which are group elements
    /// (elliptic curve points)
    coefficients: Vec<CoefficientCommitment<C>>,
}

impl<C: Ciphersuite> PolynomialCommitment<C> {
    /// Creates a `PolynomialCommitment` out of a vector of `CoefficientCommitment`
    /// This function raises Error if the vector is empty or if it is the all identity vector
    pub fn new(coefcommitments: &[CoefficientCommitment<C>]) -> Result<Self, ProtocolError> {
        // count the number of zero coeffs before spotting the first non-zero from the back
        let count = coefcommitments
            .iter()
            .rposition(|x| x.value() != C::Group::identity())
            .map_or(0, |i| i + 1);

        if count == 0 {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }

        let new_coefficients: Vec<_> = coefcommitments.iter().take(count).copied().collect();

        Ok(Self {
            coefficients: new_coefficients,
        })
    }

    /// Returns the coefficients of the
    pub fn get_coefficients(&self) -> Vec<CoefficientCommitment<C>> {
        self.coefficients.clone()
    }

    /// Outputs the degree of the committed polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Adds two `PolynomialCommitment` together
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
        Self::new(&coefficients)
    }

    /// Evaluates the committed polynomial on zero (outputs the constant term)
    /// Returns error if the polynomial is empty
    pub fn eval_at_zero(&self) -> Result<CoefficientCommitment<C>, ProtocolError> {
        self.coefficients
            .first()
            .copied()
            .ok_or(ProtocolError::EmptyOrZeroCoefficients)
    }

    /// Evaluates the committed polynomial at a specific value
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

    /// Evaluates the committed polynomial at a participant identifier.
    pub fn eval_at_participant(
        &self,
        participant: Participant,
    ) -> Result<CoefficientCommitment<C>, ProtocolError> {
        let id = participant.scalar::<C>();
        self.eval_at_point(id)
    }

    /// Computes polynomial interpolation on the exponent at a specific point
    /// using a sequence of sorted coefficient commitments.
    /// Input requirements:
    ///     * identifiers MUST be pairwise distinct and of length greater than 1
    ///     * shares and identifiers must be of same length
    ///     * identifier[i] corresponds to share[i]
    // Returns error if shares' and identifiers' lengths are distinct or less than or equals to 1.
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
        }

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
        Self::new(&coeffcommitment)
    }

    /// Set the constant value of this polynomial to a new group element
    /// Aborts if the output polynomial would be the identity or empty
    pub fn set_non_identity_constant(
        &mut self,
        v: CoefficientCommitment<C>,
    ) -> Result<(), ProtocolError> {
        let coefficients_len = self.coefficients.len();
        self.coefficients
            .first_mut()
            .map_or(Err(ProtocolError::EmptyOrZeroCoefficients), |first| {
                if v.value() == C::Group::identity() && coefficients_len == 1 {
                    Err(ProtocolError::EmptyOrZeroCoefficients)
                } else {
                    *first = v;
                    Ok(())
                }
            })
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
        Self::new(&coefficients)
            .map_err(|err| serde::de::Error::custom(format!("ProtocolError: {err}")))
    }
}
