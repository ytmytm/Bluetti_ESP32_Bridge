#ifndef PUBLISH_CACHE_H
#define PUBLISH_CACHE_H

#include <stddef.h>
#include <string>
#include <vector>

class PublishCache {
public:
  explicit PublishCache(size_t field_count);

  bool shouldPublish(size_t field_index, const std::string& value);
  void reset();

private:
  std::vector<bool> has_value_;
  std::vector<std::string> values_;
};

#endif
