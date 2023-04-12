%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%% 
%% validate_options has been adaptet from eleveldb.erl
%% Copyright (c) 2010-2017 Basho Technologies, Inc
%% 

-module(vmq_storage_engine_rocksdb_util).

-export([validate_options/2]).

-define(COMPRESSION_ENUM, [snappy, lz4, zlib, bzip2, lz4, lz4h, zstd, false]).
-type compression_algorithm() :: snappy | lz4 | false.

-spec option_types(block | db | cf | open | read | write) -> [{atom(), bool | integer | [compression_algorithm()] | any}].
option_types(block) ->
    [{no_block_cache, bool},
    {block_size, integer},
    {block_cache, any},
    {block_cache_size, integer},
    {bloom_filter_policy, any},
    {format_version, integer},
    {cache_index_and_filter_blocks, bool}];
option_types(cf) ->
    [{block_cache_size_mb_for_point_lookup, integer},
     {memtable_memory_budget, integer},
     {write_buffer_size, integer},
     {max_write_buffer_number, integer},
     {min_write_buffer_number_to_merge, integer},
     {enable_blob_files, bool},
     {min_blob_size, integer},
     {blob_file_size, integer},
     {blob_compression_type, any},
     {enable_blob_garbage_collection, bool},
     {blob_garbage_collection_age_cutoff, any},
     {blob_garbage_collection_force_threshold, any},
     {blob_compaction_readahead_size, integer},
     {blob_file_starting_level, integer},
     {blob_cache, any},
     {prepopulate_blob_cache, any},
     {compression, ?COMPRESSION_ENUM},
     {bottommost_compression, ?COMPRESSION_ENUM},
     {compression_opts, any},
     {bottommost_compression_opts, any},
     {num_levels, integer},
     {level0_file_num_compaction_trigger, integer},
     {level0_slowdown_writes_trigger, integer},
     {level0_stop_writes_trigger, integer},
     {target_file_size_base, integer},
     {target_file_size_multiplier, integer},
     {max_bytes_for_level_base, integer},
     {max_bytes_for_level_multiplier, integer},
     {max_compaction_bytes, integer},
     {arena_block_size, integer},
     {disable_auto_compactions, integer},
     {compaction_style, any},
     {compaction_pri, any},
     {filter_deletes, bool},
     {max_sequential_skip_in_iterations, integer},
     {inplace_update_support, bool},
     {inplace_update_num_locks, integer},
     {table_factory_block_cache_size, integer},
     {in_memory_mode, bool},
     {level_compaction_dynamic_level_bytes, bool},
     {optimize_filters_for_hits, bool},
     {prefix_extractor, any},
     {capped_prefix_transform, integer},
     {merge_operator, any}
    ];
option_types(db) ->
    [{create_if_missing, bool},
     {error_if_exists, bool},
     {create_missing_column_families, bool},
     {max_open_files, integer},
     {max_total_wal_size, integer},
     {use_fsync, bool},
     {db_log_dir, any},
     {wal_dir, any},
     {delete_obsolete_files_period_micros, integer},
     {max_background_jobs, integer},
     {max_background_compactions, integer},
     {max_background_flushes, integer},
     {max_log_file_size, integer},
     {log_file_time_to_roll, integer},
     {keep_log_file_num, integer},
     {max_manifest_file_size, integer},
     {table_cache_numshardbits, integer},
     {wal_ttl_seconds, integer},
     {manual_wal_flush, bool},
     {wal_size_limit_mb, integer},
     {manifest_preallocation_size, integer},
     {allow_mmap_reads, bool},
     {allow_mmap_writes, bool},
     {is_fd_close_on_exec, bool},
     {stats_dump_period_sec, integer},
     {advise_random_on_open, bool},
     {access_hint, any},
     {compaction_readahead_size, integer},
     {use_adaptive_mutex, bool},
     {bytes_per_sync, integer},
     {skip_stats_update_on_db_open, bool},
     {wal_recovery_mode, any},
     {allow_concurrent_memtable_write, bool},
     {enable_write_thread_adaptive_yield, bool},
     {db_write_buffer_size, integer},
     {in_memory, bool},
     {rate_limiter, any},
     {sst_file_manager, any},
     {write_buffer_manager, any},
     {max_subcompactions, integer},
     {atomic_flush, bool},
     {use_direct_reads, bool},
     {use_direct_io_for_flush_and_compaction, bool},
     {enable_pipelined_write, bool},
     {unordered_write, bool},
     {two_write_queues, bool},
     {statistics, any},
     {paranoid_checks, bool},
     {total_threads, integer}
 ];

option_types(open) ->
    option_types(db)++option_types(cf)++option_types(block);
option_types(read) ->
    [{verify_checksums, bool},
     {read_tier, any},
     {iterate_upper_bound, any},
     {iterate_lower_bound, any},
     {fill_cache, bool},
     {tailing, bool},
     {total_order_seek, bool},
     {prefix_same_as_start, bool},
     {snapshot, any}];
option_types(write) ->
     [{sync, bool},
      {disable_wal, bool},
      {ignore_missing_column_families, bool},
      {no_slowdown, bool},
      {low_pri, bool}].
validate_type({_Key, bool}, true)                            -> true;
validate_type({_Key, bool}, false)                           -> true;
validate_type({_Key, integer}, Value) when is_integer(Value) -> true;
validate_type({_Key, any}, _Value)                           -> true;
validate_type({_Key, ?COMPRESSION_ENUM}, snappy)             -> true;
validate_type({_Key, ?COMPRESSION_ENUM}, lz4)                -> true;
validate_type({_Key, ?COMPRESSION_ENUM}, false)              -> true;
validate_type(_, _)                                          -> false.

validate_options(Type, Opts) ->
Types = option_types(Type),
lists:partition(fun({K, V}) ->
KType = lists:keyfind(K, 1, Types),
validate_type(KType, V)
end, Opts).    
