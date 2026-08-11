/*
 * stats.h
 *
 * This files contains all statistic collected by various part of the driver.
 *
 * TODO: encapsulate into an class.
 */

#ifndef STATS_H
#define STATS_H

#include <inttypes.h>
#include <atomic>

extern uint64_t add_message_calls;

extern uint64_t inet_packets;
extern uint64_t inet_volume;

extern uint64_t inet_out_packets;
extern uint64_t inet_out_volume;
extern uint64_t inet_in_packets;
extern uint64_t inet_in_volume;

extern uint64_t inet_socket_in_packets;
extern uint64_t inet_socket_in_volume;
extern uint64_t inet_socket_out_packets;
extern uint64_t inet_socket_out_volume;

// Compiler stats
extern uint64_t total_num_prog_blocks, total_prog_block_size;

// Object stats
extern uint64_t tot_alloc_object, tot_alloc_object_size;
extern uint64_t tot_dangling_object;

// Array stats
extern uint64_t num_arrays, total_array_size;

// Class stats
extern uint64_t num_classes, total_class_size;

// Mapping stats
extern std::atomic<uint64_t> num_mappings;
extern std::atomic<uint64_t> total_mapping_size;
extern std::atomic<uint64_t> total_mapping_nodes;

// Apply cache stats
extern uint64_t apply_cache_lookups;
extern uint64_t apply_cache_hits;
extern uint64_t apply_cache_items;

// string allocation stats
extern std::atomic<uint64_t> num_distinct_strings;
extern std::atomic<uint64_t> bytes_distinct_strings;
extern std::atomic<uint64_t> allocd_strings;
extern std::atomic<uint64_t> allocd_bytes;
extern std::atomic<uint64_t> overhead_bytes;

#endif
