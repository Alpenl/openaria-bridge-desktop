use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RationalError {
    #[error("a rational numerator and denominator must both be non-zero")]
    Zero,
    #[error("rational arithmetic overflow")]
    Overflow,
    #[error("{frames} frames at {fps_num}/{fps_den} fps do not map exactly to time base {time_num}/{time_den}")]
    InexactFrameTime {
        frames: u64,
        fps_num: u32,
        fps_den: u32,
        time_num: u32,
        time_den: u32,
    },
}

/// A positive, reduced rational used for frame rates and media time bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Rational {
    numerator: u32,
    denominator: u32,
}

impl Rational {
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, RationalError> {
        if numerator == 0 || denominator == 0 {
            return Err(RationalError::Zero);
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    #[must_use]
    pub fn numerator(self) -> u32 {
        self.numerator
    }

    #[must_use]
    pub fn denominator(self) -> u32 {
        self.denominator
    }

    pub fn frames_in_whole_seconds(self, seconds: u32) -> Result<u64, RationalError> {
        let product = u64::from(self.numerator)
            .checked_mul(u64::from(seconds))
            .ok_or(RationalError::Overflow)?;
        let denominator = u64::from(self.denominator);
        if product % denominator != 0 {
            return Err(RationalError::InexactFrameTime {
                frames: product,
                fps_num: self.numerator,
                fps_den: self.denominator,
                time_num: 1,
                time_den: 1,
            });
        }
        Ok(product / denominator)
    }

    pub fn ticks_for_frames(self, frames: u64, time_base: Rational) -> Result<u64, RationalError> {
        // seconds = frames * fps.den / fps.num
        // ticks = seconds * time_base.den / time_base.num
        let numerator = u128::from(frames)
            .checked_mul(u128::from(self.denominator))
            .and_then(|value| value.checked_mul(u128::from(time_base.denominator)))
            .ok_or(RationalError::Overflow)?;
        let denominator = u128::from(self.numerator)
            .checked_mul(u128::from(time_base.numerator))
            .ok_or(RationalError::Overflow)?;
        if numerator % denominator != 0 {
            return Err(RationalError::InexactFrameTime {
                frames,
                fps_num: self.numerator,
                fps_den: self.denominator,
                time_num: time_base.numerator,
                time_den: time_base.denominator,
            });
        }
        u64::try_from(numerator / denominator).map_err(|_| RationalError::Overflow)
    }
}

const fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thirty_and_sixty_fps_map_exactly_to_ninety_kilohertz() {
        let time_base = Rational::new(1, 90_000).expect("time base");
        assert_eq!(
            Rational::new(30, 1)
                .expect("fps")
                .ticks_for_frames(1, time_base)
                .expect("ticks"),
            3_000
        );
        assert_eq!(
            Rational::new(60, 1)
                .expect("fps")
                .ticks_for_frames(1, time_base)
                .expect("ticks"),
            1_500
        );
    }
}
