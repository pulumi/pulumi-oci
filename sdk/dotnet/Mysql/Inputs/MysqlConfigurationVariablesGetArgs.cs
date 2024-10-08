// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlConfigurationVariablesGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// ("autocommit")
        /// </summary>
        [Input("autocommit")]
        public Input<bool>? Autocommit { get; set; }

        /// <summary>
        /// If enabled, the server stores all temporary tables on disk rather than in memory.
        /// 
        /// bigTables corresponds to the MySQL server variable [big_tables](https://dev.mysql.com/doc/refman/en/server-system-variables.html#sysvar_big_tables).
        /// </summary>
        [Input("bigTables")]
        public Input<bool>? BigTables { get; set; }

        /// <summary>
        /// Sets the binary log expiration period in seconds. binlogExpireLogsSeconds corresponds to the MySQL binary logging system variable [binlog_expire_logs_seconds](https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#sysvar_binlog_expire_logs_seconds).
        /// </summary>
        [Input("binlogExpireLogsSeconds")]
        public Input<int>? BinlogExpireLogsSeconds { get; set; }

        /// <summary>
        /// Configures the amount of table metadata added to the binary log when using row-based logging. binlogRowMetadata corresponds to the MySQL binary logging system variable [binlog_row_metadata](https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#sysvar_binlog_row_metadata).
        /// </summary>
        [Input("binlogRowMetadata")]
        public Input<string>? BinlogRowMetadata { get; set; }

        /// <summary>
        /// When set to PARTIAL_JSON, this enables use of a space-efficient binary log format for updates that modify only a small portion of a JSON document. binlogRowValueOptions corresponds to the MySQL binary logging system variable [binlog_row_value_options](https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#sysvar_binlog_row_value_options).
        /// </summary>
        [Input("binlogRowValueOptions")]
        public Input<string>? BinlogRowValueOptions { get; set; }

        /// <summary>
        /// Enables compression for transactions that are written to binary log files on this server. binlogTransactionCompression corresponds to the MySQL binary logging system variable [binlog_transaction_compression](https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#sysvar_binlog_transaction_compression).
        /// </summary>
        [Input("binlogTransactionCompression")]
        public Input<bool>? BinlogTransactionCompression { get; set; }

        /// <summary>
        /// ("completion_type")
        /// </summary>
        [Input("completionType")]
        public Input<string>? CompletionType { get; set; }

        /// <summary>
        /// The number of seconds that the mysqld server waits for a connect packet before responding with Bad handshake.
        /// 
        /// connectTimeout corresponds to the MySQL system variable [connect_timeout](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_connect_timeout)
        /// 
        /// Increasing the connect_timeout value might help if clients frequently encounter errors of the form "Lost connection to MySQL server at 'XXX', system error: errno".
        /// </summary>
        [Input("connectTimeout")]
        public Input<int>? ConnectTimeout { get; set; }

        /// <summary>
        /// Set the chunking size for updates to the global memory usage counter Global_connection_memory.
        /// 
        /// connectionMemoryChunkSize corresponds to the MySQL system variable [connection_memory_chunk_size](https://dev.mysql.com/doc/refman/en/server-system-variables.html#sysvar_connection_memory_chunk_size).
        /// </summary>
        [Input("connectionMemoryChunkSize")]
        public Input<int>? ConnectionMemoryChunkSize { get; set; }

        /// <summary>
        /// Set the maximum amount of memory that can be used by a single user connection.
        /// 
        /// connectionMemoryLimit corresponds to the MySQL system variable [connection_memory_limit](https://dev.mysql.com/doc/refman/en/server-system-variables.html#sysvar_connection_memory_limit).
        /// </summary>
        [Input("connectionMemoryLimit")]
        public Input<string>? ConnectionMemoryLimit { get; set; }

        /// <summary>
        /// ("cte_max_recursion_depth")
        /// </summary>
        [Input("cteMaxRecursionDepth")]
        public Input<string>? CteMaxRecursionDepth { get; set; }

        /// <summary>
        /// ("default_authentication_plugin")
        /// </summary>
        [Input("defaultAuthenticationPlugin")]
        public Input<string>? DefaultAuthenticationPlugin { get; set; }

        /// <summary>
        /// ("foreign_key_checks")
        /// </summary>
        [Input("foreignKeyChecks")]
        public Input<bool>? ForeignKeyChecks { get; set; }

        /// <summary>
        /// ("generated_random_password_length") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("generatedRandomPasswordLength")]
        public Input<int>? GeneratedRandomPasswordLength { get; set; }

        /// <summary>
        /// Set the total amount of memory that can be used by all user connections.
        /// 
        /// globalConnectionMemoryLimit corresponds to the MySQL system variable [global_connection_memory_limit](https://dev.mysql.com/doc/refman/en/server-system-variables.html#sysvar_global_connection_memory_limit).
        /// </summary>
        [Input("globalConnectionMemoryLimit")]
        public Input<string>? GlobalConnectionMemoryLimit { get; set; }

        /// <summary>
        /// Determines whether the MySQL server calculates Global_connection_memory.
        /// 
        /// globalConnectionMemoryTracking corresponds to the MySQL system variable [global_connection_memory_tracking](https://dev.mysql.com/doc/refman/en/server-system-variables.html#sysvar_global_connection_memory_tracking).
        /// </summary>
        [Input("globalConnectionMemoryTracking")]
        public Input<bool>? GlobalConnectionMemoryTracking { get; set; }

        /// <summary>
        /// * EVENTUAL: Both RO and RW transactions do not wait for preceding transactions to be applied before executing. A RW transaction does not wait for other members to apply a transaction. This means that a transaction could be externalized on one member before the others. This also means that in the event of a primary failover, the new primary can accept new RO and RW transactions before the previous primary transactions are all applied. RO transactions could result in outdated values, RW transactions could result in a rollback due to conflicts.
        /// * BEFORE_ON_PRIMARY_FAILOVER: New RO or RW transactions with a newly elected primary that is applying backlog from the old primary are held (not applied) until any backlog has been applied. This ensures that when a primary failover happens, intentionally or not, clients always see the latest value on the primary. This guarantees consistency, but means that clients must be able to handle the delay in the event that a backlog is being applied. Usually this delay should be minimal, but does depend on the size of the backlog.
        /// * BEFORE: A RW transaction waits for all preceding transactions to complete before being applied. A RO transaction waits for all preceding transactions to complete before being executed. This ensures that this transaction reads the latest value by only affecting the latency of the transaction. This reduces the overhead of synchronization on every RW transaction, by ensuring synchronization is used only on RO transactions. This consistency level also includes the consistency guarantees provided by BEFORE_ON_PRIMARY_FAILOVER.
        /// * AFTER: A RW transaction waits until its changes have been applied to all of the other members. This value has no effect on RO transactions. This mode ensures that when a transaction is committed on the local member, any subsequent transaction reads the written value or a more recent value on any group member. Use this mode with a group that is used for predominantly RO operations to ensure that applied RW transactions are applied everywhere once they commit. This could be used by your application to ensure that subsequent reads fetch the latest data which includes the latest writes. This reduces the overhead of synchronization on every RO transaction, by ensuring synchronization is used only on RW transactions. This consistency level also includes the consistency guarantees provided by BEFORE_ON_PRIMARY_FAILOVER.
        /// * BEFORE_AND_AFTER: A RW transaction waits for 1) all preceding transactions to complete before being applied and 2) until its changes have been applied on other members. A RO transaction waits for all preceding transactions to complete before execution takes place. This consistency level also includes the consistency guarantees provided by BEFORE_ON_PRIMARY_FAILOVER.
        /// </summary>
        [Input("groupReplicationConsistency")]
        public Input<string>? GroupReplicationConsistency { get; set; }

        /// <summary>
        /// ("information_schema_stats_expiry")
        /// </summary>
        [Input("informationSchemaStatsExpiry")]
        public Input<int>? InformationSchemaStatsExpiry { get; set; }

        /// <summary>
        /// Specifies the percentage of the most recently used pages for each buffer pool to read out and dump.
        /// 
        /// innodbBufferPoolDumpPct corresponds to the MySQL InnoDB system variable [innodb_buffer_pool_dump_pct](https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_buffer_pool_dump_pct).
        /// 
        /// The range is 1 to 100. The default value is 25.
        /// 
        /// For example, if there are 4 buffer pools with 100 pages each, and innodb_buffer_pool_dump_pct is set to 25, the 25 most recently used pages from each buffer pool are dumped.
        /// </summary>
        [Input("innodbBufferPoolDumpPct")]
        public Input<int>? InnodbBufferPoolDumpPct { get; set; }

        /// <summary>
        /// ("innodb_buffer_pool_instances")
        /// </summary>
        [Input("innodbBufferPoolInstances")]
        public Input<int>? InnodbBufferPoolInstances { get; set; }

        /// <summary>
        /// The size (in bytes) of the buffer pool, that is, the memory area where InnoDB caches table and index data.
        /// 
        /// innodbBufferPoolSize corresponds to the MySQL server system variable [innodb_buffer_pool_size](https://dev.mysql.com/doc/refman/en/innodb-parameters.html#sysvar_innodb_buffer_pool_size).
        /// 
        /// The default and maximum values depend on the amount of RAM provisioned by the shape. See [Default User Variables](https://www.terraform.io/mysql-database/doc/configuring-db-system.html#GUID-B5504C19-F6F4-4DAB-8506-189A4E8F4A6A).
        /// </summary>
        [Input("innodbBufferPoolSize")]
        public Input<string>? InnodbBufferPoolSize { get; set; }

        /// <summary>
        /// innodbDdlBufferSize corresponds to the MySQL system variable [innodb_ddl_buffer_size] (https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_ddl_buffer_size)
        /// </summary>
        [Input("innodbDdlBufferSize")]
        public Input<string>? InnodbDdlBufferSize { get; set; }

        /// <summary>
        /// innodbDdlThreads corresponds to the MySQL system variable [innodb_ddl_threads] (https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_ddl_threads)
        /// </summary>
        [Input("innodbDdlThreads")]
        public Input<int>? InnodbDdlThreads { get; set; }

        /// <summary>
        /// ("innodb_ft_enable_stopword")
        /// </summary>
        [Input("innodbFtEnableStopword")]
        public Input<bool>? InnodbFtEnableStopword { get; set; }

        /// <summary>
        /// ("innodb_ft_max_token_size")
        /// </summary>
        [Input("innodbFtMaxTokenSize")]
        public Input<int>? InnodbFtMaxTokenSize { get; set; }

        /// <summary>
        /// ("innodb_ft_min_token_size")
        /// </summary>
        [Input("innodbFtMinTokenSize")]
        public Input<int>? InnodbFtMinTokenSize { get; set; }

        /// <summary>
        /// ("innodb_ft_num_word_optimize")
        /// </summary>
        [Input("innodbFtNumWordOptimize")]
        public Input<int>? InnodbFtNumWordOptimize { get; set; }

        /// <summary>
        /// ("innodb_ft_result_cache_limit")
        /// </summary>
        [Input("innodbFtResultCacheLimit")]
        public Input<string>? InnodbFtResultCacheLimit { get; set; }

        /// <summary>
        /// ("innodb_ft_server_stopword_table")
        /// </summary>
        [Input("innodbFtServerStopwordTable")]
        public Input<string>? InnodbFtServerStopwordTable { get; set; }

        /// <summary>
        /// ("innodb_lock_wait_timeout")
        /// </summary>
        [Input("innodbLockWaitTimeout")]
        public Input<int>? InnodbLockWaitTimeout { get; set; }

        /// <summary>
        /// Enables dedicated log writer threads for writing redo log records from the log buffer to the system buffers and flushing the system buffers to the redo log files.
        /// 
        /// This is the MySQL variable "innodb_log_writer_threads". For more information, please see the [MySQL documentation](https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_log_writer_threads)
        /// </summary>
        [Input("innodbLogWriterThreads")]
        public Input<bool>? InnodbLogWriterThreads { get; set; }

        /// <summary>
        /// The desired maximum purge lag in terms of transactions.
        /// 
        /// InnoDB maintains a list of transactions that have index records delete-marked by UPDATE or DELETE operations. The length of the list is the purge lag.
        /// 
        /// If this value is exceeded, a delay is imposed on INSERT, UPDATE, and DELETE operations to allow time for purge to catch up.
        /// 
        /// The default value is 0, which means there is no maximum purge lag and no delay.
        /// 
        /// innodbMaxPurgeLag corresponds to the MySQL server system variable [innodb_max_purge_lag](https://dev.mysql.com/doc/refman/en/innodb-parameters.html#sysvar_innodb_max_purge_lag).
        /// </summary>
        [Input("innodbMaxPurgeLag")]
        public Input<string>? InnodbMaxPurgeLag { get; set; }

        /// <summary>
        /// The maximum delay in microseconds for the delay imposed when the innodb_max_purge_lag threshold is exceeded.
        /// 
        /// The specified innodb_max_purge_lag_delay value is an upper limit on the delay period.
        /// 
        /// innodbMaxPurgeLagDelay corresponds to the MySQL server system variable [innodb_max_purge_lag_delay](https://dev.mysql.com/doc/refman/en/innodb-parameters.html#sysvar_innodb_max_purge_lag_delay).
        /// </summary>
        [Input("innodbMaxPurgeLagDelay")]
        public Input<int>? InnodbMaxPurgeLagDelay { get; set; }

        /// <summary>
        /// The number of index pages to sample when estimating cardinality and other statistics for an indexed column, such as those calculated by ANALYZE TABLE.
        /// 
        /// innodbStatsPersistentSamplePages corresponds to the MySQL InnoDB system variable [innodb_stats_persistent_sample_pages](https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_stats_persistent_sample_pages)
        /// 
        /// innodb_stats_persistent_sample_pages only applies when innodb_stats_persistent is enabled for a table; when innodb_stats_persistent is disabled, innodb_stats_transient_sample_pages applies instead.
        /// </summary>
        [Input("innodbStatsPersistentSamplePages")]
        public Input<string>? InnodbStatsPersistentSamplePages { get; set; }

        /// <summary>
        /// The number of index pages to sample when estimating cardinality and other statistics for an indexed column, such as those calculated by [ANALYZE TABLE](https://dev.mysql.com/doc/refman/8.0/en/analyze-table.html).
        /// 
        /// innodbStatsTransientSamplePages corresponds to the MySQL InnoDB system variable [innodb_stats_transient_sample_pages](https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_stats_transient_sample_pages)
        /// 
        /// innodb_stats_transient_sample_pages only applies when innodb_stats_persistent is disabled for a table; when innodb_stats_persistent is enabled, innodb_stats_persistent_sample_pages applies instead.
        /// 
        /// innodb_stats_persistent is ON by default and cannot be changed. It is possible to override it using the STATS_PERSISTENT clause of the [CREATE TABLE](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) and [ALTER TABLE](https://dev.mysql.com/doc/refman/8.0/en/alter-table.html) statements.
        /// </summary>
        [Input("innodbStatsTransientSamplePages")]
        public Input<string>? InnodbStatsTransientSamplePages { get; set; }

        /// <summary>
        /// The number of seconds the server waits for activity on an interactive connection before closing it.
        /// 
        /// interactiveTimeout corresponds to the MySQL system variable. [interactive_timeout](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_interactive_timeout)
        /// </summary>
        [Input("interactiveTimeout")]
        public Input<int>? InteractiveTimeout { get; set; }

        /// <summary>
        /// ("local_infile")
        /// </summary>
        [Input("localInfile")]
        public Input<bool>? LocalInfile { get; set; }

        /// <summary>
        /// ("mandatory_roles")
        /// </summary>
        [Input("mandatoryRoles")]
        public Input<string>? MandatoryRoles { get; set; }

        /// <summary>
        /// The maximum size of one packet or any generated/intermediate string.
        /// 
        /// This is the mysql variable "max_allowed_packet".
        /// </summary>
        [Input("maxAllowedPacket")]
        public Input<int>? MaxAllowedPacket { get; set; }

        /// <summary>
        /// Sets the size of the transaction cache.
        /// 
        /// maxBinlogCacheSize corresponds to the MySQL server system variable [max_binlog_cache_size](https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#sysvar_max_binlog_cache_size).
        /// </summary>
        [Input("maxBinlogCacheSize")]
        public Input<string>? MaxBinlogCacheSize { get; set; }

        /// <summary>
        /// ("max_connect_errors")
        /// </summary>
        [Input("maxConnectErrors")]
        public Input<string>? MaxConnectErrors { get; set; }

        /// <summary>
        /// ("max_connections")
        /// </summary>
        [Input("maxConnections")]
        public Input<int>? MaxConnections { get; set; }

        /// <summary>
        /// ("max_execution_time")
        /// </summary>
        [Input("maxExecutionTime")]
        public Input<string>? MaxExecutionTime { get; set; }

        /// <summary>
        /// This variable sets the maximum size to which user-created MEMORY tables are permitted to grow.
        /// 
        /// maxHeapTableSize corresponds to the MySQL system variable [max_heap_table_size](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_max_heap_table_size)
        /// </summary>
        [Input("maxHeapTableSize")]
        public Input<string>? MaxHeapTableSize { get; set; }

        /// <summary>
        /// ("max_prepared_stmt_count")
        /// </summary>
        [Input("maxPreparedStmtCount")]
        public Input<int>? MaxPreparedStmtCount { get; set; }

        /// <summary>
        /// ("mysql_firewall_mode")
        /// </summary>
        [Input("mysqlFirewallMode")]
        public Input<bool>? MysqlFirewallMode { get; set; }

        /// <summary>
        /// DEPRECATED -- typo of mysqlx_zstd_default_compression_level. variable will be ignored.
        /// </summary>
        [Input("mysqlZstdDefaultCompressionLevel")]
        public Input<int>? MysqlZstdDefaultCompressionLevel { get; set; }

        /// <summary>
        /// The number of seconds X Plugin waits for the first packet to be received from newly connected clients.
        /// 
        /// mysqlxConnectTimeout corresponds to the MySQL X Plugin system variable [mysqlx_connect_timeout](https://dev.mysql.com/doc/refman/8.0/en/x-plugin-options-system-variables.html#sysvar_mysqlx_connect_timeout)
        /// </summary>
        [Input("mysqlxConnectTimeout")]
        public Input<int>? MysqlxConnectTimeout { get; set; }

        /// <summary>
        /// Set the default compression level for the deflate algorithm. ("mysqlx_deflate_default_compression_level")
        /// </summary>
        [Input("mysqlxDeflateDefaultCompressionLevel")]
        public Input<int>? MysqlxDeflateDefaultCompressionLevel { get; set; }

        /// <summary>
        /// Limit the upper bound of accepted compression levels for the deflate algorithm. ("mysqlx_deflate_max_client_compression_level")
        /// </summary>
        [Input("mysqlxDeflateMaxClientCompressionLevel")]
        public Input<int>? MysqlxDeflateMaxClientCompressionLevel { get; set; }

        /// <summary>
        /// ("mysqlx_document_id_unique_prefix") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("mysqlxDocumentIdUniquePrefix")]
        public Input<int>? MysqlxDocumentIdUniquePrefix { get; set; }

        /// <summary>
        /// ("mysqlx_enable_hello_notice") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("mysqlxEnableHelloNotice")]
        public Input<bool>? MysqlxEnableHelloNotice { get; set; }

        /// <summary>
        /// ("mysqlx_idle_worker_thread_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("mysqlxIdleWorkerThreadTimeout")]
        public Input<int>? MysqlxIdleWorkerThreadTimeout { get; set; }

        /// <summary>
        /// The number of seconds to wait for interactive clients to timeout.
        /// 
        /// mysqlxInteractiveTimeout corresponds to the MySQL X Plugin system variable. [mysqlx_interactive_timeout](https://dev.mysql.com/doc/refman/8.0/en/x-plugin-options-system-variables.html#sysvar_mysqlx_interactive_timeout)
        /// </summary>
        [Input("mysqlxInteractiveTimeout")]
        public Input<int>? MysqlxInteractiveTimeout { get; set; }

        /// <summary>
        /// Set the default compression level for the lz4 algorithm. ("mysqlx_lz4_default_compression_level")
        /// </summary>
        [Input("mysqlxLz4defaultCompressionLevel")]
        public Input<int>? MysqlxLz4defaultCompressionLevel { get; set; }

        /// <summary>
        /// Limit the upper bound of accepted compression levels for the lz4 algorithm. ("mysqlx_lz4_max_client_compression_level")
        /// </summary>
        [Input("mysqlxLz4maxClientCompressionLevel")]
        public Input<int>? MysqlxLz4maxClientCompressionLevel { get; set; }

        /// <summary>
        /// The maximum size of network packets that can be received by X Plugin.
        /// 
        /// This is the mysql variable "mysqlx_max_allowed_packet".
        /// </summary>
        [Input("mysqlxMaxAllowedPacket")]
        public Input<int>? MysqlxMaxAllowedPacket { get; set; }

        /// <summary>
        /// ("mysqlx_min_worker_threads") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("mysqlxMinWorkerThreads")]
        public Input<int>? MysqlxMinWorkerThreads { get; set; }

        /// <summary>
        /// The number of seconds that X Plugin waits for blocking read operations to complete. After this time, if the read operation is not successful, X Plugin closes the connection and returns a warning notice with the error code ER_IO_READ_ERROR to the client application.
        /// 
        /// mysqlxReadTimeout corresponds to the MySQL X Plugin system variable [mysqlx_read_timeout](https://dev.mysql.com/doc/refman/8.0/en/x-plugin-options-system-variables.html#sysvar_mysqlx_read_timeout)
        /// </summary>
        [Input("mysqlxReadTimeout")]
        public Input<int>? MysqlxReadTimeout { get; set; }

        /// <summary>
        /// The number of seconds that X Plugin waits for activity on a connection.
        /// 
        /// mysqlxWaitTimeout corresponds to the MySQL X Plugin system variable. [mysqlx_wait_timeout](https://dev.mysql.com/doc/refman/8.0/en/x-plugin-options-system-variables.html#sysvar_mysqlx_wait_timeout)
        /// </summary>
        [Input("mysqlxWaitTimeout")]
        public Input<int>? MysqlxWaitTimeout { get; set; }

        /// <summary>
        /// The number of seconds that X Plugin waits for blocking write operations to complete. After this time, if the write operation is not successful, X Plugin closes the connection.
        /// 
        /// mysqlxReadmysqlxWriteTimeoutTimeout corresponds to the MySQL X Plugin system variable [mysqlx_write_timeout](https://dev.mysql.com/doc/refman/8.0/en/x-plugin-options-system-variables.html#sysvar_mysqlx_write_timeout)
        /// </summary>
        [Input("mysqlxWriteTimeout")]
        public Input<int>? MysqlxWriteTimeout { get; set; }

        /// <summary>
        /// Set the default compression level for the zstd algorithm. ("mysqlx_zstd_default_compression_level")
        /// </summary>
        [Input("mysqlxZstdDefaultCompressionLevel")]
        public Input<int>? MysqlxZstdDefaultCompressionLevel { get; set; }

        /// <summary>
        /// Limit the upper bound of accepted compression levels for the zstd algorithm. ("mysqlx_zstd_max_client_compression_level")
        /// </summary>
        [Input("mysqlxZstdMaxClientCompressionLevel")]
        public Input<int>? MysqlxZstdMaxClientCompressionLevel { get; set; }

        /// <summary>
        /// The number of seconds to wait for more data from a connection before aborting the read.
        /// 
        /// netReadTimeout corresponds to the MySQL system variable [net_read_timeout](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_net_read_timeout)
        /// </summary>
        [Input("netReadTimeout")]
        public Input<int>? NetReadTimeout { get; set; }

        /// <summary>
        /// The number of seconds to wait for a block to be written to a connection before aborting the write.
        /// 
        /// netWriteTimeout corresponds to the MySQL system variable [net_write_timeout](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_net_write_timeout)
        /// </summary>
        [Input("netWriteTimeout")]
        public Input<int>? NetWriteTimeout { get; set; }

        /// <summary>
        /// ("parser_max_mem_size")
        /// </summary>
        [Input("parserMaxMemSize")]
        public Input<string>? ParserMaxMemSize { get; set; }

        /// <summary>
        /// ("query_alloc_block_size") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("queryAllocBlockSize")]
        public Input<string>? QueryAllocBlockSize { get; set; }

        /// <summary>
        /// ("query_prealloc_size") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        [Input("queryPreallocSize")]
        public Input<string>? QueryPreallocSize { get; set; }

        /// <summary>
        /// regexpTimeLimit corresponds to the MySQL system variable [regexp_time_limit] (https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_regexp_time_limit)
        /// </summary>
        [Input("regexpTimeLimit")]
        public Input<int>? RegexpTimeLimit { get; set; }

        /// <summary>
        /// Each session that must perform a sort allocates a buffer of this size.
        /// 
        /// sortBufferSize corresponds to the MySQL system variable [sort_buffer_size](https://dev.mysql.com/doc/refman/en/server-system-variables.html#sysvar_sort_buffer_size)
        /// </summary>
        [Input("sortBufferSize")]
        public Input<string>? SortBufferSize { get; set; }

        /// <summary>
        /// ("sql_mode")
        /// </summary>
        [Input("sqlMode")]
        public Input<string>? SqlMode { get; set; }

        /// <summary>
        /// ("sql_require_primary_key")
        /// </summary>
        [Input("sqlRequirePrimaryKey")]
        public Input<bool>? SqlRequirePrimaryKey { get; set; }

        /// <summary>
        /// ("sql_warnings")
        /// </summary>
        [Input("sqlWarnings")]
        public Input<bool>? SqlWarnings { get; set; }

        /// <summary>
        /// Controls whether the thread pool uses dedicated listener threads. If enabled, a listener thread in each thread group is dedicated to the task of listening for network events from clients, ensuring that the maximum number of query worker threads is no more than the value specified by threadPoolMaxTransactionsLimit. threadPoolDedicatedListeners corresponds to the MySQL Database Service-specific system variable thread_pool_dedicated_listeners.
        /// </summary>
        [Input("threadPoolDedicatedListeners")]
        public Input<bool>? ThreadPoolDedicatedListeners { get; set; }

        /// <summary>
        /// Limits the maximum number of open transactions to the defined value. The default value is 0, which enforces no limit. threadPoolMaxTransactionsLimit corresponds to the MySQL Database Service-specific system variable thread_pool_max_transactions_limit.
        /// </summary>
        [Input("threadPoolMaxTransactionsLimit")]
        public Input<int>? ThreadPoolMaxTransactionsLimit { get; set; }

        /// <summary>
        /// Initializes the time zone for each client that connects.
        /// 
        /// This corresponds to the MySQL System Variable "time_zone".
        /// 
        /// The values can be given in one of the following formats, none of which are case-sensitive:
        /// * As a string indicating an offset from UTC of the form [H]H:MM, prefixed with a + or -, such as '+10:00', '-6:00', or '+05:30'. The permitted range is '-13:59' to '+14:00', inclusive.
        /// * As a named time zone, as defined by the "IANA Time Zone database", such as 'Europe/Helsinki', 'US/Eastern', 'MET', or 'UTC'.
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        /// <summary>
        /// The maximum size of internal in-memory temporary tables. This variable does not apply to user-created MEMORY tables.
        /// 
        /// tmp_table_size corresponds to the MySQL system variable [tmp_table_size](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_tmp_table_size)
        /// </summary>
        [Input("tmpTableSize")]
        public Input<string>? TmpTableSize { get; set; }

        /// <summary>
        /// ("transaction_isolation")
        /// </summary>
        [Input("transactionIsolation")]
        public Input<string>? TransactionIsolation { get; set; }

        /// <summary>
        /// The number of seconds the server waits for activity on a noninteractive connection before closing it.
        /// 
        /// waitTimeout corresponds to the MySQL system variable. [wait_timeout](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_wait_timeout)
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("waitTimeout")]
        public Input<int>? WaitTimeout { get; set; }

        public MysqlConfigurationVariablesGetArgs()
        {
        }
        public static new MysqlConfigurationVariablesGetArgs Empty => new MysqlConfigurationVariablesGetArgs();
    }
}
