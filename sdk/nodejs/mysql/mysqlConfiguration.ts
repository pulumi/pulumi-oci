// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Mysql Configuration resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Creates a new Configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMysqlConfiguration = new oci.mysql.MysqlConfiguration("test_mysql_configuration", {
 *     compartmentId: compartmentId,
 *     shapeName: testShape.name,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: mysqlConfigurationDescription,
 *     displayName: mysqlConfigurationDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     initVariables: {
 *         lowerCaseTableNames: mysqlConfigurationInitVariablesLowerCaseTableNames,
 *     },
 *     parentConfigurationId: testConfiguration.id,
 *     variables: {
 *         autoIncrementIncrement: mysqlConfigurationVariablesAutoIncrementIncrement,
 *         autoIncrementOffset: mysqlConfigurationVariablesAutoIncrementOffset,
 *         autocommit: mysqlConfigurationVariablesAutocommit,
 *         bigTables: mysqlConfigurationVariablesBigTables,
 *         binlogExpireLogsSeconds: mysqlConfigurationVariablesBinlogExpireLogsSeconds,
 *         binlogGroupCommitSyncDelay: mysqlConfigurationVariablesBinlogGroupCommitSyncDelay,
 *         binlogGroupCommitSyncNoDelayCount: mysqlConfigurationVariablesBinlogGroupCommitSyncNoDelayCount,
 *         binlogRowMetadata: mysqlConfigurationVariablesBinlogRowMetadata,
 *         binlogRowValueOptions: mysqlConfigurationVariablesBinlogRowValueOptions,
 *         binlogTransactionCompression: mysqlConfigurationVariablesBinlogTransactionCompression,
 *         blockEncryptionMode: mysqlConfigurationVariablesBlockEncryptionMode,
 *         characterSetServer: mysqlConfigurationVariablesCharacterSetServer,
 *         collationServer: mysqlConfigurationVariablesCollationServer,
 *         completionType: mysqlConfigurationVariablesCompletionType,
 *         connectTimeout: mysqlConfigurationVariablesConnectTimeout,
 *         connectionMemoryChunkSize: mysqlConfigurationVariablesConnectionMemoryChunkSize,
 *         connectionMemoryLimit: mysqlConfigurationVariablesConnectionMemoryLimit,
 *         cteMaxRecursionDepth: mysqlConfigurationVariablesCteMaxRecursionDepth,
 *         defaultAuthenticationPlugin: mysqlConfigurationVariablesDefaultAuthenticationPlugin,
 *         explainFormat: mysqlConfigurationVariablesExplainFormat,
 *         explicitDefaultsForTimestamp: mysqlConfigurationVariablesExplicitDefaultsForTimestamp,
 *         foreignKeyChecks: mysqlConfigurationVariablesForeignKeyChecks,
 *         generatedRandomPasswordLength: mysqlConfigurationVariablesGeneratedRandomPasswordLength,
 *         globalConnectionMemoryLimit: mysqlConfigurationVariablesGlobalConnectionMemoryLimit,
 *         globalConnectionMemoryTracking: mysqlConfigurationVariablesGlobalConnectionMemoryTracking,
 *         groupConcatMaxLen: mysqlConfigurationVariablesGroupConcatMaxLen,
 *         groupReplicationConsistency: mysqlConfigurationVariablesGroupReplicationConsistency,
 *         informationSchemaStatsExpiry: mysqlConfigurationVariablesInformationSchemaStatsExpiry,
 *         innodbAdaptiveHashIndex: mysqlConfigurationVariablesInnodbAdaptiveHashIndex,
 *         innodbAutoincLockMode: mysqlConfigurationVariablesInnodbAutoincLockMode,
 *         innodbBufferPoolDumpPct: mysqlConfigurationVariablesInnodbBufferPoolDumpPct,
 *         innodbBufferPoolInstances: mysqlConfigurationVariablesInnodbBufferPoolInstances,
 *         innodbBufferPoolSize: mysqlConfigurationVariablesInnodbBufferPoolSize,
 *         innodbChangeBuffering: mysqlConfigurationVariablesInnodbChangeBuffering,
 *         innodbDdlBufferSize: mysqlConfigurationVariablesInnodbDdlBufferSize,
 *         innodbDdlThreads: mysqlConfigurationVariablesInnodbDdlThreads,
 *         innodbFtEnableStopword: mysqlConfigurationVariablesInnodbFtEnableStopword,
 *         innodbFtMaxTokenSize: mysqlConfigurationVariablesInnodbFtMaxTokenSize,
 *         innodbFtMinTokenSize: mysqlConfigurationVariablesInnodbFtMinTokenSize,
 *         innodbFtNumWordOptimize: mysqlConfigurationVariablesInnodbFtNumWordOptimize,
 *         innodbFtResultCacheLimit: mysqlConfigurationVariablesInnodbFtResultCacheLimit,
 *         innodbFtServerStopwordTable: mysqlConfigurationVariablesInnodbFtServerStopwordTable,
 *         innodbLockWaitTimeout: mysqlConfigurationVariablesInnodbLockWaitTimeout,
 *         innodbLogWriterThreads: mysqlConfigurationVariablesInnodbLogWriterThreads,
 *         innodbMaxPurgeLag: mysqlConfigurationVariablesInnodbMaxPurgeLag,
 *         innodbMaxPurgeLagDelay: mysqlConfigurationVariablesInnodbMaxPurgeLagDelay,
 *         innodbNumaInterleave: mysqlConfigurationVariablesInnodbNumaInterleave,
 *         innodbOnlineAlterLogMaxSize: mysqlConfigurationVariablesInnodbOnlineAlterLogMaxSize,
 *         innodbRedoLogCapacity: mysqlConfigurationVariablesInnodbRedoLogCapacity,
 *         innodbRollbackOnTimeout: mysqlConfigurationVariablesInnodbRollbackOnTimeout,
 *         innodbSortBufferSize: mysqlConfigurationVariablesInnodbSortBufferSize,
 *         innodbStatsPersistentSamplePages: mysqlConfigurationVariablesInnodbStatsPersistentSamplePages,
 *         innodbStatsTransientSamplePages: mysqlConfigurationVariablesInnodbStatsTransientSamplePages,
 *         innodbStrictMode: mysqlConfigurationVariablesInnodbStrictMode,
 *         innodbUndoLogTruncate: mysqlConfigurationVariablesInnodbUndoLogTruncate,
 *         interactiveTimeout: mysqlConfigurationVariablesInteractiveTimeout,
 *         joinBufferSize: mysqlConfigurationVariablesJoinBufferSize,
 *         localInfile: mysqlConfigurationVariablesLocalInfile,
 *         longQueryTime: mysqlConfigurationVariablesLongQueryTime,
 *         mandatoryRoles: mysqlConfigurationVariablesMandatoryRoles,
 *         maxAllowedPacket: mysqlConfigurationVariablesMaxAllowedPacket,
 *         maxBinlogCacheSize: mysqlConfigurationVariablesMaxBinlogCacheSize,
 *         maxConnectErrors: mysqlConfigurationVariablesMaxConnectErrors,
 *         maxConnections: mysqlConfigurationVariablesMaxConnections,
 *         maxExecutionTime: mysqlConfigurationVariablesMaxExecutionTime,
 *         maxHeapTableSize: mysqlConfigurationVariablesMaxHeapTableSize,
 *         maxPreparedStmtCount: mysqlConfigurationVariablesMaxPreparedStmtCount,
 *         maxSeeksForKey: mysqlConfigurationVariablesMaxSeeksForKey,
 *         maxUserConnections: mysqlConfigurationVariablesMaxUserConnections,
 *         mysqlFirewallMode: mysqlConfigurationVariablesMysqlFirewallMode,
 *         mysqlZstdDefaultCompressionLevel: mysqlConfigurationVariablesMysqlZstdDefaultCompressionLevel,
 *         mysqlxConnectTimeout: mysqlConfigurationVariablesMysqlxConnectTimeout,
 *         mysqlxDeflateDefaultCompressionLevel: mysqlConfigurationVariablesMysqlxDeflateDefaultCompressionLevel,
 *         mysqlxDeflateMaxClientCompressionLevel: mysqlConfigurationVariablesMysqlxDeflateMaxClientCompressionLevel,
 *         mysqlxDocumentIdUniquePrefix: mysqlConfigurationVariablesMysqlxDocumentIdUniquePrefix,
 *         mysqlxEnableHelloNotice: mysqlConfigurationVariablesMysqlxEnableHelloNotice,
 *         mysqlxIdleWorkerThreadTimeout: mysqlConfigurationVariablesMysqlxIdleWorkerThreadTimeout,
 *         mysqlxInteractiveTimeout: mysqlConfigurationVariablesMysqlxInteractiveTimeout,
 *         mysqlxLz4defaultCompressionLevel: mysqlConfigurationVariablesMysqlxLz4defaultCompressionLevel,
 *         mysqlxLz4maxClientCompressionLevel: mysqlConfigurationVariablesMysqlxLz4maxClientCompressionLevel,
 *         mysqlxMaxAllowedPacket: mysqlConfigurationVariablesMysqlxMaxAllowedPacket,
 *         mysqlxMinWorkerThreads: mysqlConfigurationVariablesMysqlxMinWorkerThreads,
 *         mysqlxReadTimeout: mysqlConfigurationVariablesMysqlxReadTimeout,
 *         mysqlxWaitTimeout: mysqlConfigurationVariablesMysqlxWaitTimeout,
 *         mysqlxWriteTimeout: mysqlConfigurationVariablesMysqlxWriteTimeout,
 *         mysqlxZstdDefaultCompressionLevel: mysqlConfigurationVariablesMysqlxZstdDefaultCompressionLevel,
 *         mysqlxZstdMaxClientCompressionLevel: mysqlConfigurationVariablesMysqlxZstdMaxClientCompressionLevel,
 *         netReadTimeout: mysqlConfigurationVariablesNetReadTimeout,
 *         netWriteTimeout: mysqlConfigurationVariablesNetWriteTimeout,
 *         optimizerSwitch: mysqlConfigurationVariablesOptimizerSwitch,
 *         parserMaxMemSize: mysqlConfigurationVariablesParserMaxMemSize,
 *         queryAllocBlockSize: mysqlConfigurationVariablesQueryAllocBlockSize,
 *         queryPreallocSize: mysqlConfigurationVariablesQueryPreallocSize,
 *         rangeOptimizerMaxMemSize: mysqlConfigurationVariablesRangeOptimizerMaxMemSize,
 *         regexpTimeLimit: mysqlConfigurationVariablesRegexpTimeLimit,
 *         relayLogSpaceLimit: mysqlConfigurationVariablesRelayLogSpaceLimit,
 *         replicaNetTimeout: mysqlConfigurationVariablesReplicaNetTimeout,
 *         replicaParallelWorkers: mysqlConfigurationVariablesReplicaParallelWorkers,
 *         replicaTypeConversions: mysqlConfigurationVariablesReplicaTypeConversions,
 *         requireSecureTransport: mysqlConfigurationVariablesRequireSecureTransport,
 *         skipNameResolve: mysqlConfigurationVariablesSkipNameResolve,
 *         sortBufferSize: mysqlConfigurationVariablesSortBufferSize,
 *         sqlGenerateInvisiblePrimaryKey: mysqlConfigurationVariablesSqlGenerateInvisiblePrimaryKey,
 *         sqlMode: mysqlConfigurationVariablesSqlMode,
 *         sqlRequirePrimaryKey: mysqlConfigurationVariablesSqlRequirePrimaryKey,
 *         sqlWarnings: mysqlConfigurationVariablesSqlWarnings,
 *         tableDefinitionCache: mysqlConfigurationVariablesTableDefinitionCache,
 *         tableOpenCache: mysqlConfigurationVariablesTableOpenCache,
 *         temptableMaxRam: mysqlConfigurationVariablesTemptableMaxRam,
 *         threadPoolDedicatedListeners: mysqlConfigurationVariablesThreadPoolDedicatedListeners,
 *         threadPoolMaxTransactionsLimit: mysqlConfigurationVariablesThreadPoolMaxTransactionsLimit,
 *         threadPoolQueryThreadsPerGroup: mysqlConfigurationVariablesThreadPoolQueryThreadsPerGroup,
 *         threadPoolSize: mysqlConfigurationVariablesThreadPoolSize,
 *         threadPoolTransactionDelay: mysqlConfigurationVariablesThreadPoolTransactionDelay,
 *         timeZone: mysqlConfigurationVariablesTimeZone,
 *         tmpTableSize: mysqlConfigurationVariablesTmpTableSize,
 *         transactionIsolation: mysqlConfigurationVariablesTransactionIsolation,
 *         waitTimeout: mysqlConfigurationVariablesWaitTimeout,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * MysqlConfigurations can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Mysql/mysqlConfiguration:MysqlConfiguration test_mysql_configuration "configurations/{configurationId}"
 * ```
 */
export class MysqlConfiguration extends pulumi.CustomResource {
    /**
     * Get an existing MysqlConfiguration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MysqlConfigurationState, opts?: pulumi.CustomResourceOptions): MysqlConfiguration {
        return new MysqlConfiguration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Mysql/mysqlConfiguration:MysqlConfiguration';

    /**
     * Returns true if the given object is an instance of MysqlConfiguration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MysqlConfiguration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MysqlConfiguration.__pulumiType;
    }

    /**
     * The OCID of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) User-provided data about the Configuration.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the Configuration.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * User-defined service variables set only at DB system initialization. These variables cannot be changed later at runtime.
     */
    public readonly initVariables!: pulumi.Output<outputs.Mysql.MysqlConfigurationInitVariables>;
    /**
     * The OCID of the Configuration from which the new Configuration is derived. The values in CreateConfigurationDetails.variables supersede the variables of the parent Configuration.
     */
    public readonly parentConfigurationId!: pulumi.Output<string>;
    /**
     * The name of the associated Shape.
     */
    public readonly shapeName!: pulumi.Output<string>;
    /**
     * The current state of the Configuration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the Configuration was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the Configuration was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The Configuration type, DEFAULT or CUSTOM.
     */
    public /*out*/ readonly type!: pulumi.Output<string>;
    /**
     * User-defined service variables.
     */
    public readonly variables!: pulumi.Output<outputs.Mysql.MysqlConfigurationVariables>;

    /**
     * Create a MysqlConfiguration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MysqlConfigurationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MysqlConfigurationArgs | MysqlConfigurationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MysqlConfigurationState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["initVariables"] = state ? state.initVariables : undefined;
            resourceInputs["parentConfigurationId"] = state ? state.parentConfigurationId : undefined;
            resourceInputs["shapeName"] = state ? state.shapeName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["variables"] = state ? state.variables : undefined;
        } else {
            const args = argsOrState as MysqlConfigurationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.shapeName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shapeName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["initVariables"] = args ? args.initVariables : undefined;
            resourceInputs["parentConfigurationId"] = args ? args.parentConfigurationId : undefined;
            resourceInputs["shapeName"] = args ? args.shapeName : undefined;
            resourceInputs["variables"] = args ? args.variables : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["type"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MysqlConfiguration.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MysqlConfiguration resources.
 */
export interface MysqlConfigurationState {
    /**
     * The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) User-provided data about the Configuration.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the Configuration.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * User-defined service variables set only at DB system initialization. These variables cannot be changed later at runtime.
     */
    initVariables?: pulumi.Input<inputs.Mysql.MysqlConfigurationInitVariables>;
    /**
     * The OCID of the Configuration from which the new Configuration is derived. The values in CreateConfigurationDetails.variables supersede the variables of the parent Configuration.
     */
    parentConfigurationId?: pulumi.Input<string>;
    /**
     * The name of the associated Shape.
     */
    shapeName?: pulumi.Input<string>;
    /**
     * The current state of the Configuration.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the Configuration was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the Configuration was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The Configuration type, DEFAULT or CUSTOM.
     */
    type?: pulumi.Input<string>;
    /**
     * User-defined service variables.
     */
    variables?: pulumi.Input<inputs.Mysql.MysqlConfigurationVariables>;
}

/**
 * The set of arguments for constructing a MysqlConfiguration resource.
 */
export interface MysqlConfigurationArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) User-provided data about the Configuration.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the Configuration.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * User-defined service variables set only at DB system initialization. These variables cannot be changed later at runtime.
     */
    initVariables?: pulumi.Input<inputs.Mysql.MysqlConfigurationInitVariables>;
    /**
     * The OCID of the Configuration from which the new Configuration is derived. The values in CreateConfigurationDetails.variables supersede the variables of the parent Configuration.
     */
    parentConfigurationId?: pulumi.Input<string>;
    /**
     * The name of the associated Shape.
     */
    shapeName: pulumi.Input<string>;
    /**
     * User-defined service variables.
     */
    variables?: pulumi.Input<inputs.Mysql.MysqlConfigurationVariables>;
}
