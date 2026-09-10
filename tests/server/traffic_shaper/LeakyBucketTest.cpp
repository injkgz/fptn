/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <chrono>
#include <cstddef>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "traffic_shaper/leaky_bucket.h"

namespace {

using fptn::traffic_shaper::LeakyBucket;

// 8000 bit/s is exactly 1000 byte/s - the arithmetic stays readable.
constexpr std::size_t kBitsPerSecond = 8000;
constexpr std::size_t kBytesPerSecond = kBitsPerSecond / 8;

// The bucket stamps its own creation time from the real clock, so the test
// clock has to start from there rather than from the epoch.
std::chrono::steady_clock::time_point Start() {
  return std::chrono::steady_clock::now();
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(LeakyBucketTest, AdmitsPacketsUpToTheBudget) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  for (int i = 0; i < 10; ++i) {
    EXPECT_TRUE(bucket.CheckSpeedLimitAt(100, now)) << "packet " << i;
  }
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(100, now));
}

TEST(LeakyBucketTest, BoundaryPacketFitsExactly) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  EXPECT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, now));
}

TEST(LeakyBucketTest, RejectedPacketIsNotCounted) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));
  const auto before = bucket.FullDataAmount();
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, now));
  EXPECT_EQ(bucket.FullDataAmount(), before);
}

// The bucket has to drain in proportion to time, not on a full second of
// silence.
TEST(LeakyBucketTest, LeaksProportionallyToElapsedTime) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));
  ASSERT_FALSE(bucket.CheckSpeedLimitAt(1, now));

  const auto half = now + std::chrono::milliseconds(500);
  EXPECT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond / 2, half));
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, half));
}

// The regression this class was fixed for: a dense stream with no pauses used
// to be blacked out for most of every second.
TEST(LeakyBucketTest, DenseStreamKeepsFlowingAtTheLimit) {
  constexpr std::size_t kPacket = 100;
  LeakyBucket bucket(kBitsPerSecond);
  auto now = Start();

  std::size_t admitted = 0;
  for (int ms = 0; ms < 10000; ++ms) {
    now += std::chrono::milliseconds(1);
    if (bucket.CheckSpeedLimitAt(kPacket, now)) {
      admitted += kPacket;
    }
  }

  // Ten seconds at 1000 byte/s, plus at most one bucket depth of burst.
  const std::size_t expected = kBytesPerSecond * 10;
  EXPECT_GE(admitted, expected * 95 / 100);
  EXPECT_LE(admitted, expected + kBytesPerSecond);
}

// A steady stream and a bursty one must get the same share over time - the
// old code gave the bursty one far more.
TEST(LeakyBucketTest, SteadyAndBurstyStreamsGetTheSameShare) {
  constexpr std::size_t kPacket = 100;
  constexpr int kMillis = 10000;

  LeakyBucket steady(kBitsPerSecond);
  auto now = Start();
  std::size_t steady_admitted = 0;
  for (int ms = 0; ms < kMillis; ++ms) {
    now += std::chrono::milliseconds(1);
    if (steady.CheckSpeedLimitAt(kPacket, now)) {
      steady_admitted += kPacket;
    }
  }

  LeakyBucket bursty(kBitsPerSecond);
  now = Start();
  std::size_t bursty_admitted = 0;
  for (int ms = 0; ms < kMillis; ++ms) {
    now += std::chrono::milliseconds(1);
    // Idle for 90 ms, then hammer for 10.
    if (ms % 100 < 90) {
      continue;
    }
    for (int burst = 0; burst < 20; ++burst) {
      if (bursty.CheckSpeedLimitAt(kPacket, now)) {
        bursty_admitted += kPacket;
      }
    }
  }

  const auto larger = std::max(steady_admitted, bursty_admitted);
  const auto smaller = std::min(steady_admitted, bursty_admitted);
  EXPECT_GE(smaller * 100 / larger, 90U)
      << "steady=" << steady_admitted << " bursty=" << bursty_admitted;
}

TEST(LeakyBucketTest, IdleTimeDoesNotOverfillTheBucket) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();
  ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));

  // Ten seconds of silence must not buy ten seconds of budget.
  const auto later = now + std::chrono::seconds(10);
  std::size_t admitted = 0;
  while (bucket.CheckSpeedLimitAt(100, later)) {
    admitted += 100;
    ASSERT_LE(admitted, kBytesPerSecond * 2) << "bucket never filled up";
  }
  EXPECT_EQ(admitted, kBytesPerSecond);
}

TEST(LeakyBucketTest, SubMillisecondGapsDoNotLoseTheBudget) {
  LeakyBucket bucket(kBitsPerSecond);
  auto now = Start();

  std::size_t admitted = 0;
  for (int i = 0; i < 10000; ++i) {
    now += std::chrono::microseconds(100);
    if (bucket.CheckSpeedLimitAt(10, now)) {
      admitted += 10;
    }
  }

  // One second of traffic in 100 us steps: the budget must be spent, not lost
  // to rounding.
  EXPECT_GE(admitted, kBytesPerSecond * 95 / 100);
}

// A zero limit means "no limit": the server builds a shaper unconditionally,
// and a bucket of zero would silence the tunnel instead of slowing it.
TEST(LeakyBucketTest, ZeroLimitAdmitsEverything) {
  LeakyBucket bucket(0);
  const auto now = Start();

  for (int i = 0; i < 1000; ++i) {
    EXPECT_TRUE(bucket.CheckSpeedLimitAt(1500, now));
  }
  EXPECT_EQ(bucket.FullDataAmount(), 1500U * 1000U);
}

TEST(LeakyBucketTest, HugeLimitDoesNotOverflow) {
  // 10 Gbit/s and a long silence: the intermediate product must stay in 64
  // bits and the drain must not wrap.
  LeakyBucket bucket(10ULL * 1000 * 1000 * 1000);
  const auto now = Start();
  ASSERT_TRUE(bucket.CheckSpeedLimitAt(1500, now));

  const auto much_later = now + std::chrono::hours(24);
  EXPECT_TRUE(bucket.CheckSpeedLimitAt(1500, much_later));
}

TEST(LeakyBucketTest, BitsAreConvertedToBytesByEight) {
  LeakyBucket bucket(800);  // 100 byte/s
  const auto now = Start();

  EXPECT_TRUE(bucket.CheckSpeedLimitAt(100, now));
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, now));
}

TEST(LeakyBucketTest, FullDataAmountCountsOnlyAdmittedBytes) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  ASSERT_TRUE(bucket.CheckSpeedLimitAt(400, now));
  ASSERT_TRUE(bucket.CheckSpeedLimitAt(400, now));
  ASSERT_FALSE(bucket.CheckSpeedLimitAt(400, now));

  EXPECT_EQ(bucket.FullDataAmount(), 800U);
}
