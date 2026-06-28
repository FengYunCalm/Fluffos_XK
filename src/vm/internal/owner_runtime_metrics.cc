#include "vm/internal/owner_runtime_metrics.h"

OwnerRuntimeMetricsSnapshot OwnerRuntimeMetrics::snapshot() const {
  OwnerRuntimeMetricsSnapshot snapshot;
#define OWNER_RUNTIME_METRIC_LOAD_FIELD(name, initial) \
  snapshot.name = name.load(std::memory_order_relaxed);
  OWNER_RUNTIME_METRIC_FIELDS(OWNER_RUNTIME_METRIC_LOAD_FIELD)
#undef OWNER_RUNTIME_METRIC_LOAD_FIELD
  return snapshot;
}
