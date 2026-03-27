mod commitment;
mod polynomial;

pub use commitment::PolynomialCommitment;
pub use polynomial::Polynomial;

use frost_core::{serialization::SerializableScalar, Field, Group, Scalar};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::ciphersuite::Ciphersuite;
use crate::errors::ProtocolError;

/// Computes the Lagrange coefficient (a.k.a. Lagrange basis polynomial)
/// evaluated at point x.
/// `lambda_i(x)` = `\prod_j` (x - `x_j`)/(`x_i` - `x_j`)  where j != i
///
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
        for x_j in points_set {
            if *x_i == *x_j {
                contains_i = true;
                continue;
            }
            num = num * (*x - *x_j);
            den = den * (*x_i - *x_j);
        }
    } else {
        for x_j in points_set {
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

/// Computes all Lagrange basis coefficients `lambda_i(x)` for the nodes in `points_set`,
/// evaluated at a single point `x`, using batch operations to reduce field inversions.
///
/// Lagrange coefficient definition:
///   `lambda_i(x)` = \prod_{j!=i} (x - `x_j`) / (`x_i` - `x_j`)
///
/// Inputs:
/// - `points_set` = {`x_0`, `x_1`, …}. Each `lambda_i` corresponds to `x_i` ∈ `points_set`.
/// - `x`: the evaluation point. If `None`, it is treated as 0.
///
/// Requirements:
/// - `points_set.len() > 1`.
/// - All `x_i` are distinct.
///
/// Early exit:
/// - If x equals some `x_k` in `points_set`, return the Kronecker delta vector:
///   `lambda_k(x)=1` and `lambda_i(x)=0` for i!=k.
///
/// Batch computation strategy:
/// 1) Denominators: for each i, compute `d_i` = \prod_{j!=i} (`x_i` - `x_j`),
///    then invert all `d_i` together in a single batch. This reduces n separate
///    inversions to 1 batch inversion (O(n) instead of O(n^2)).
/// 2) Numerators: compute the global numerator N = `\prod_j` (x - `x_j`),
///    then for each i obtain `n_i` = N / (x - `x_i`) using batch inversion of (x - `x_i`).
/// 3) Combine: `lambda_i(x)` = `n_i` * (d_i^-1).
///
/// Returns:
/// - `Vec<SerializableScalar<C>>`: Lagrange coefficients corresponding to each `x_i`.
///
/// Example (over reals for clarity):
/// - `points_set` = [1, 2, 4], x = 3:
///   lambda(3) = [-1/3, 1, 1/3]   // sums to 1
/// - `points_set` = [1, 2, 4], x = 2:
///   lambda(2) = [0, 1, 0]        // x equals x₁
/// - `points_set` = [1, 3, 4], x = None (so x=0):
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
        let i = u32::try_from(i).map_err(|_| ProtocolError::InvalidInterpolationArguments)?;
        let is_equal = p.ct_eq(x);
        // If is_equal is true, select 'i', otherwise keep the current k_index_val
        kronecker_index =
            CtOption::conditional_select(&kronecker_index, &CtOption::new(i, is_equal), is_equal);
    }

    if let Some(kronecker_index_value) = kronecker_index.into_option() {
        let kronecker_index_value = usize::try_from(kronecker_index_value)
            .map_err(|_| ProtocolError::InvalidInterpolationArguments)?;

        let mut coeffs = vec![SerializableScalar(<C::Group as Group>::Field::zero()); n];

        if let Some(coeff_value) = coeffs.get_mut(kronecker_index_value) {
            *coeff_value = SerializableScalar(<C::Group as Group>::Field::one());
        }
        return Ok(coeffs);
    }

    // Compute denominators d_i = \prod_{j!=i} (x_i - x_j) for each point x_i in points_set.
    // This corresponds to the denominator of the Lagrange basis polynomial lambda_i(x):
    //    lambda_i(x) = prod_{j!=i} (x - x_j) / (x_i - x_j)
    // By computing all d_i here, we can invert them in a single batch later, which
    // is much faster than inverting each individually.
    let mut denominators = Vec::with_capacity(n);
    for (i, point_set_i) in points_set.iter().enumerate() {
        let mut den = <C::Group as Group>::Field::one();
        for (j, point_set_j) in points_set.iter().enumerate() {
            if i == j {
                continue;
            }
            den = den * (*point_set_i - *point_set_j);
        }
        denominators.push(den);
    }

    // Invert all denominators in one batch for efficiency
    let inv_denominators = batch_invert::<C>(&denominators)?;

    // Special case: x = 0
    let (numerator_prod, inv_factors) = if *x == zero {
        // Compute P = \prod_j (-1)* *x_j
        let mut p = <C::Group as Group>::Field::one();
        for x_i in points_set {
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
        for x_i in points_set {
            let x_minus_xi = *x - *x_i;
            full_numerator = full_numerator * x_minus_xi;
            x_minus_xi_vec.push(x_minus_xi);
        }
        let inv_x_minus_xi_vec = batch_invert::<C>(&x_minus_xi_vec)?;
        (full_numerator, inv_x_minus_xi_vec)
    };

    // Compute final Lagrange coefficients
    let mut lagrange_coeffs = Vec::with_capacity(n);
    for (inv_factors_i, inv_denominators_i) in inv_factors.into_iter().zip(inv_denominators) {
        // For each i, compute the numerator n_i = N / (x - x_i), where N = Prod_j (x - x_j).
        // This is done by multiplying the total product `numerator_prod` by the pre-computed
        // inverse of the term `(x - x_i)` (or `x_i` if x is zero).
        let num_i = numerator_prod * inv_factors_i;
        lagrange_coeffs.push(SerializableScalar(num_i * inv_denominators_i));
    }

    Ok(lagrange_coeffs)
}

/// Batch inversion of a list of field elements.
/// Returns a vector of inverses in the same order.
/// Uses the standard prefix-product / suffix-product trick for O(n) inversions instead of O(n^2).
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
    for ((inverted_i, products_i_1), values_i) in inverted
        .iter_mut()
        .skip(1)
        .rev()
        .zip(products.iter().rev().skip(1))
        .zip(values.iter().skip(1).rev())
    {
        *inverted_i = *products_i_1 * inv_last;
        inv_last = inv_last * *values_i;
    }
    let inverted_0 = inverted
        .first_mut()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;
    *inverted_0 = inv_last;

    Ok(inverted)
}

#[cfg(test)]
mod test {
    use std::ops::Neg;

    use super::*;
    use crate::errors::ProtocolError;
    use crate::participants::Participant;
    use crate::test_utils::{
        generate_participants, generate_participants_with_random_ids, MockCryptoRng,
    };
    use frost_core::keys::CoefficientCommitment;
    use frost_core::Field;
    use frost_secp256k1::{Secp256K1Group, Secp256K1ScalarField, Secp256K1Sha256};
    use k256::Scalar;
    use rand_core::{RngCore, SeedableRng};
    type C = Secp256K1Sha256;

    #[test]
    fn abort_no_polynomial() {
        let poly = Polynomial::<C>::new(&[]);
        assert!(poly.is_err(), "Polynomial should be raising error");

        let vec = vec![Secp256K1ScalarField::zero(); 10];
        let poly = Polynomial::<C>::new(&vec);
        assert!(poly.is_err(), "Polynomial should be raising error");
    }

    #[test]
    fn abort_no_polynomial_commitments() {
        let poly = PolynomialCommitment::<C>::new(&[]);
        assert!(poly.is_err(), "Polynomial should be raising error");
        let vec = vec![CoefficientCommitment::<C>::new(Secp256K1Group::identity()); 10];
        let poly = PolynomialCommitment::new(&vec);
        assert!(poly.is_err(), "Polynomial should be raising error");
    }

    #[test]
    fn test_get_coefficients_poly() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 50;
        let mut coefficients = Vec::with_capacity(poly_size);

        for _ in 0..poly_size {
            coefficients
                .push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng));
        }

        let poly = Polynomial::<C>::new(&coefficients).unwrap();
        for (a, b) in poly.get_coefficients().iter().zip(coefficients) {
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn test_get_coefficients_commitments() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 50;
        let mut coefficients = Vec::with_capacity(poly_size);

        let generator = <C as frost_core::Ciphersuite>::Group::generator();
        for _ in 0..poly_size {
            let scalar = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
            coefficients.push(CoefficientCommitment::<C>::new(generator * scalar));
        }

        let poly = PolynomialCommitment::<C>::new(&coefficients).unwrap();
        for (a, b) in poly.get_coefficients().iter().zip(coefficients) {
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn test_eval_on_zero_poly() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 20;
        let mut coefficients = Vec::with_capacity(poly_size);

        let zero_coeff = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
        for i in 0..poly_size {
            if i == 0 {
                coefficients.push(zero_coeff);
            } else {
                coefficients.push(
                    <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng),
                );
            }
        }

        let poly = Polynomial::<C>::new(&coefficients).unwrap();
        // test eval_at_zero
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert_eq!(zero_coeff, poly.eval_at_zero().unwrap().0);
        assert_eq!(zero_coeff, poly.eval_at_point(point).unwrap().0);
    }

    #[test]
    fn test_eval_on_zero_commitments() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 50;
        let mut coefficients = Vec::with_capacity(poly_size);

        let generator = <C as frost_core::Ciphersuite>::Group::generator();
        let zero_coeff = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
        let zero_coeff = generator * zero_coeff;
        for i in 0..poly_size {
            if i == 0 {
                coefficients.push(CoefficientCommitment::<C>::new(zero_coeff));
            } else {
                let scalar =
                    <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
                coefficients.push(CoefficientCommitment::<C>::new(generator * scalar));
            }
        }

        let poly = PolynomialCommitment::<C>::new(&coefficients).unwrap();
        // test eval_at_zero
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert_eq!(zero_coeff, poly.eval_at_zero().unwrap().value());
        assert_eq!(zero_coeff, poly.eval_at_point(point).unwrap().value());
    }

    #[test]
    fn test_eval_on_point() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 4;
        let mut coefficients = Vec::with_capacity(poly_size);
        let mut coefficients_com = Vec::with_capacity(poly_size);

        // X^3 + X^2 + X + 1
        for _ in 0..poly_size {
            coefficients.push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::one());
            coefficients_com.push(CoefficientCommitment::<C>::new(
                <<C as frost_core::Ciphersuite>::Group as Group>::generator(),
            ));
        }

        let poly = Polynomial::<C>::new(&coefficients).unwrap();
        let polycom = PolynomialCommitment::<C>::new(&coefficients_com).unwrap();

        for _ in 1..50 {
            // test eval_at_zero
            let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
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
            );
        }
    }

    #[test]
    fn test_eval_on_participant() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 6;
        let mut coefficients = Vec::with_capacity(poly_size);
        let mut coefficients_com = Vec::with_capacity(poly_size);

        // X^5 + X^3 + X
        for i in 0..poly_size {
            if i % 2 == 1 {
                coefficients.push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::one());
                coefficients_com.push(CoefficientCommitment::<C>::new(
                    <<C as frost_core::Ciphersuite>::Group as Group>::generator(),
                ));
            } else {
                coefficients.push(<<C as frost_core::Ciphersuite>::Group as Group>::Field::zero());
                coefficients_com.push(CoefficientCommitment::<C>::new(
                    <<C as frost_core::Ciphersuite>::Group as Group>::identity(),
                ));
            }
        }

        let poly = Polynomial::<C>::new(&coefficients).unwrap();
        let polycom = PolynomialCommitment::<C>::new(&coefficients_com).unwrap();

        for _ in 1..50 {
            let participant = Participant::from(rng.next_u32());
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
            );
        }
    }

    #[test]
    fn test_commit_polynomial() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 4;
        let mut coefficients = Vec::with_capacity(poly_size);
        let mut coefficients_com = Vec::with_capacity(poly_size);
        for _ in 0..poly_size {
            let scalar = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
            coefficients.push(scalar);
            let commitment = <<C as frost_core::Ciphersuite>::Group as Group>::generator() * scalar;
            coefficients_com.push(CoefficientCommitment::<C>::new(commitment));
        }
        let poly = Polynomial::<C>::new(&coefficients).unwrap();
        let polycom = poly.commit_polynomial().unwrap();
        for (a, b) in polycom.get_coefficients().iter().zip(coefficients_com) {
            assert_eq!(*a, b);
        }
    }

    #[test]
    fn test_generate_polynomial() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 10;
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
        let poly = Polynomial::<C>::generate_polynomial(Some(point), degree, &mut rng).unwrap();
        let coeffs = poly.get_coefficients();
        assert_eq!(coeffs.len(), degree + 1);
        assert_eq!(coeffs[0], point);
    }

    #[test]
    fn test_set_to_non_zero_poly() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let poly_size = 20;
        let mut coefficients = Vec::with_capacity(poly_size);

        let zero_coeff = <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
        for i in 0..poly_size {
            let mut rand_scalar =
                <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
            while i == 0 && zero_coeff == rand_scalar {
                rand_scalar =
                    <<C as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut rng);
            }
            coefficients.push(rand_scalar);
        }

        let mut poly = Polynomial::<C>::new(&coefficients).unwrap();
        let point = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert!(zero_coeff != poly.eval_at_zero().unwrap().0);
        assert!(zero_coeff != poly.eval_at_point(point).unwrap().0);

        poly.set_nonzero_constant(zero_coeff).unwrap();
        assert_eq!(zero_coeff, poly.eval_at_zero().unwrap().0);
        assert_eq!(zero_coeff, poly.eval_at_point(point).unwrap().0);

        let one = <<C as frost_core::Ciphersuite>::Group as Group>::Field::one();
        let mut poly_abort = Polynomial::<C>::generate_polynomial(Some(one), 0, &mut rng).unwrap();
        let zero = <<C as frost_core::Ciphersuite>::Group as Group>::Field::zero();
        assert!(poly_abort.set_nonzero_constant(zero).is_err());
    }

    #[test]
    fn test_eval_interpolation() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 5;
        let participants = (0u32..=degree).map(Participant::from).collect::<Vec<_>>();
        let ids = participants
            .iter()
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|_| SerializableScalar::<C>(Secp256K1ScalarField::random(&mut rng)))
            .collect::<Vec<_>>();
        let ref_point = Some(Secp256K1ScalarField::random(&mut rng));
        let point = ref_point.as_ref();
        assert!(Polynomial::eval_interpolation(&ids, &shares, point).is_ok());
        assert!(Polynomial::eval_interpolation(&ids, &shares, None).is_ok());
        assert!(Polynomial::eval_interpolation(&ids[..1], &shares[..1], None).is_err());
        assert!(Polynomial::eval_interpolation(&ids[..0], &shares[..0], None).is_err());
        assert!(Polynomial::eval_interpolation(&ids[..2], &shares, None).is_err());
    }

    #[test]
    fn poly_eval_interpolate() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
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
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();
        for _ in 0..100 {
            // create arbitrary point
            let point = Secp256K1ScalarField::random(&mut rng);
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
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial().unwrap();

        let participants = (0..=u32::try_from(degree).unwrap())
            .map(Participant::from)
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|p| compoly.eval_at_participant(*p).unwrap())
            .collect::<Vec<_>>();

        let ids = participants
            .iter()
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();

        let ref_point = Some(Secp256K1ScalarField::random(&mut rng));
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
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
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
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();
        for _ in 0..100 {
            // create arbitrary point
            let point = Secp256K1ScalarField::random(&mut rng);
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
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
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
                );
            } else {
                assert_eq!(extended[i].value(), coeffs[i - 1].value());
            }
        }
    }

    #[test]
    fn add_polynomial_commitments() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
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
            assert_eq!(c.value() * two, two_c.value());
        }

        coefsum.extend(&coefsum.clone());
        let extend_sum_compoly =
            PolynomialCommitment::new(&coefsum).expect("We have proper coefficients");
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
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let points = generate_participants_with_random_ids(5, &mut rng)
            .iter()
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();
        let mut result = Secp256K1ScalarField::zero();
        let target_point = Scalar::generate_biased(&mut rng);
        for point in &points {
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
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let one = Scalar::ONE;
        let zero = Scalar::ZERO;
        let target_point = Scalar::generate_biased(&mut rng);

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
        let random_point1 = Scalar::generate_biased(&mut rng);
        let random_point2 = Scalar::generate_biased(&mut rng);
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
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let degree = 10;
        let participants = generate_participants(degree + 1);

        let ids = participants
            .iter()
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();
        let point = Some(Secp256K1ScalarField::random(&mut rng));

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
    fn test_eval_exponent_interpolation_against_interpolation_times_g_at_none() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        for participants in 2..20 {
            for degree in 1..participants {
                let participants = generate_participants(participants);

                let ids = participants
                    .iter()
                    .map(Participant::scalar::<C>)
                    .collect::<Vec<_>>();

                // generate polynomial
                let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
                    .expect("Generation must not fail with overwhealming probability");

                // build all the shares
                let shares = participants
                    .iter()
                    .map(|p| poly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                let compoly = poly.commit_polynomial().unwrap();

                // build all committed shares
                let com_shares = participants
                    .iter()
                    .map(|p| compoly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                // use only degree + 1 shares to evaluate exponent
                let exponent_eval = PolynomialCommitment::eval_exponent_interpolation(
                    &ids[..=degree],
                    &com_shares[..=degree],
                    None,
                )
                .unwrap();

                // use all to evaluate the share
                let eval = Polynomial::eval_interpolation(&ids, &shares, None).unwrap();

                assert_eq!(
                    exponent_eval.value(),
                    <C as frost_core::Ciphersuite>::Group::generator() * eval.0
                );
            }
        }
    }
    #[test]
    fn test_eval_exponent_interpolation_against_interpolation_times_g_at_some() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        for participants in 2..20 {
            for degree in 1..participants {
                let participants = generate_participants(participants);

                let ids = participants
                    .iter()
                    .map(Participant::scalar::<C>)
                    .collect::<Vec<_>>();

                // generate polynomial
                let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut rng)
                    .expect("Generation must not fail with overwhealming probability");

                // build all the shares
                let shares = participants
                    .iter()
                    .map(|p| poly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                let compoly = poly.commit_polynomial().unwrap();

                // build all committed shares
                let com_shares = participants
                    .iter()
                    .map(|p| compoly.eval_at_participant(*p).unwrap())
                    .collect::<Vec<_>>();

                let point = Some(Secp256K1ScalarField::random(&mut rng));

                // use only degree + 1 shares to evaluate exponent
                let exponent_eval = PolynomialCommitment::eval_exponent_interpolation(
                    &ids[..=degree],
                    &com_shares[..=degree],
                    point.as_ref(),
                )
                .unwrap();

                // use all to evaluate the share
                let eval = Polynomial::eval_interpolation(&ids, &shares, point.as_ref()).unwrap();

                assert_eq!(
                    exponent_eval.value(),
                    <C as frost_core::Ciphersuite>::Group::generator() * eval.0
                );
            }
        }
    }

    #[test]
    fn test_generate_polynomial_overflow() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        // Test with a degree that would cause an overflow in `degree + 1`
        let Err(e) = Polynomial::<C>::generate_polynomial(None, usize::MAX, &mut rng) else {
            panic!("expected IntegerOverflow error");
        };
        assert_eq!(e, ProtocolError::IntegerOverflow);

        // Test with a degree that is at the boundary of isize::MAX
        let Err(e) = Polynomial::<C>::generate_polynomial(None, isize::MAX as usize, &mut rng)
        else {
            panic!("expected IntegerOverflow error");
        };
        assert_eq!(e, ProtocolError::IntegerOverflow);
    }

    #[test]
    fn test_polynomial_commitment_serialization() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let initial_poly = Polynomial::<C>::generate_polynomial(None, 6, &mut rng)
            .unwrap()
            .commit_polynomial()
            .unwrap();

        // When
        let poly_json = serde_json::to_string(&initial_poly).unwrap();
        let final_poly: PolynomialCommitment<C> = serde_json::from_str(&poly_json).unwrap();

        // Then
        assert_eq!(final_poly, initial_poly);
    }
}
