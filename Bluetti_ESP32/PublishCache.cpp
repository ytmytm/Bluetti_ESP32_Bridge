#include "PublishCache.h"

PublishCache::PublishCache(size_t field_count)
    : has_value_(field_count, false), values_(field_count) {}

bool PublishCache::shouldPublish(size_t field_index, const std::string& value) {
  if (field_index >= values_.size()) {
    return false;
  }

  if (has_value_[field_index] && values_[field_index] == value) {
    return false;
  }

  has_value_[field_index] = true;
  values_[field_index] = value;
  return true;
}

void PublishCache::reset() {
  for (size_t i = 0; i < has_value_.size(); i++) {
    has_value_[i] = false;
    values_[i].clear();
  }
}
