#include <unity.h>

#include "PublishCache.h"

void test_publish_cache_allows_first_value() {
  PublishCache cache(4);

  TEST_ASSERT_TRUE(cache.shouldPublish(1, "2197.02"));
}

void test_publish_cache_suppresses_identical_value() {
  PublishCache cache(4);

  TEST_ASSERT_TRUE(cache.shouldPublish(1, "2197.02"));
  TEST_ASSERT_FALSE(cache.shouldPublish(1, "2197.02"));
}

void test_publish_cache_allows_changed_value() {
  PublishCache cache(4);

  TEST_ASSERT_TRUE(cache.shouldPublish(1, "2197.02"));
  TEST_ASSERT_TRUE(cache.shouldPublish(1, "2197.03"));
}

void test_publish_cache_reset_republishes_existing_value() {
  PublishCache cache(4);

  TEST_ASSERT_TRUE(cache.shouldPublish(1, "2197.02"));
  TEST_ASSERT_FALSE(cache.shouldPublish(1, "2197.02"));
  cache.reset();
  TEST_ASSERT_TRUE(cache.shouldPublish(1, "2197.02"));
}

void test_publish_cache_rejects_out_of_range_fields() {
  PublishCache cache(4);

  TEST_ASSERT_FALSE(cache.shouldPublish(4, "ignored"));
}

int main(int argc, char **argv) {
  UNITY_BEGIN();
  RUN_TEST(test_publish_cache_allows_first_value);
  RUN_TEST(test_publish_cache_suppresses_identical_value);
  RUN_TEST(test_publish_cache_allows_changed_value);
  RUN_TEST(test_publish_cache_reset_republishes_existing_value);
  RUN_TEST(test_publish_cache_rejects_out_of_range_fields);
  return UNITY_END();
}
