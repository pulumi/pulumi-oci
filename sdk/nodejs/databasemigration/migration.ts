// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMigration = new oci.databasemigration.Migration("test_migration", {
 *     compartmentId: compartmentId,
 *     databaseCombination: migrationDatabaseCombination,
 *     sourceDatabaseConnectionId: testConnection.id,
 *     targetDatabaseConnectionId: testConnection.id,
 *     type: migrationType,
 *     advancedParameters: [{
 *         dataType: migrationAdvancedParametersDataType,
 *         name: migrationAdvancedParametersName,
 *         value: migrationAdvancedParametersValue,
 *     }],
 *     advisorSettings: {
 *         isIgnoreErrors: migrationAdvisorSettingsIsIgnoreErrors,
 *         isSkipAdvisor: migrationAdvisorSettingsIsSkipAdvisor,
 *     },
 *     bulkIncludeExcludeData: migrationBulkIncludeExcludeData,
 *     dataTransferMediumDetails: {
 *         type: migrationDataTransferMediumDetailsType,
 *         accessKeyId: testKey.id,
 *         name: migrationDataTransferMediumDetailsName,
 *         objectStorageBucket: {
 *             bucket: migrationDataTransferMediumDetailsObjectStorageBucketBucket,
 *             namespace: migrationDataTransferMediumDetailsObjectStorageBucketNamespace,
 *         },
 *         region: migrationDataTransferMediumDetailsRegion,
 *         secretAccessKey: migrationDataTransferMediumDetailsSecretAccessKey,
 *         sharedStorageMountTargetId: testMountTarget.id,
 *         source: {
 *             kind: migrationDataTransferMediumDetailsSourceKind,
 *             ociHome: migrationDataTransferMediumDetailsSourceOciHome,
 *             walletLocation: migrationDataTransferMediumDetailsSourceWalletLocation,
 *         },
 *         target: {
 *             kind: migrationDataTransferMediumDetailsTargetKind,
 *             ociHome: migrationDataTransferMediumDetailsTargetOciHome,
 *             walletLocation: migrationDataTransferMediumDetailsTargetWalletLocation,
 *         },
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: migrationDescription,
 *     displayName: migrationDisplayName,
 *     excludeObjects: [{
 *         object: migrationExcludeObjectsObject,
 *         isOmitExcludedTableFromReplication: migrationExcludeObjectsIsOmitExcludedTableFromReplication,
 *         owner: migrationExcludeObjectsOwner,
 *         schema: migrationExcludeObjectsSchema,
 *         type: migrationExcludeObjectsType,
 *     }],
 *     freeformTags: migrationFreeformTags,
 *     ggsDetails: {
 *         acceptableLag: migrationGgsDetailsAcceptableLag,
 *         extract: {
 *             longTransDuration: migrationGgsDetailsExtractLongTransDuration,
 *             performanceProfile: migrationGgsDetailsExtractPerformanceProfile,
 *         },
 *         replicat: {
 *             performanceProfile: migrationGgsDetailsReplicatPerformanceProfile,
 *         },
 *     },
 *     hubDetails: {
 *         keyId: testKey.id,
 *         restAdminCredentials: {
 *             password: migrationHubDetailsRestAdminCredentialsPassword,
 *             username: migrationHubDetailsRestAdminCredentialsUsername,
 *         },
 *         url: migrationHubDetailsUrl,
 *         vaultId: testVault.id,
 *         acceptableLag: migrationHubDetailsAcceptableLag,
 *         computeId: testCompute.id,
 *         extract: {
 *             longTransDuration: migrationHubDetailsExtractLongTransDuration,
 *             performanceProfile: migrationHubDetailsExtractPerformanceProfile,
 *         },
 *         replicat: {
 *             performanceProfile: migrationHubDetailsReplicatPerformanceProfile,
 *         },
 *     },
 *     includeObjects: [{
 *         object: migrationIncludeObjectsObject,
 *         isOmitExcludedTableFromReplication: migrationIncludeObjectsIsOmitExcludedTableFromReplication,
 *         owner: migrationIncludeObjectsOwner,
 *         schema: migrationIncludeObjectsSchema,
 *         type: migrationIncludeObjectsType,
 *     }],
 *     initialLoadSettings: {
 *         jobMode: migrationInitialLoadSettingsJobMode,
 *         compatibilities: migrationInitialLoadSettingsCompatibility,
 *         dataPumpParameters: {
 *             estimate: migrationInitialLoadSettingsDataPumpParametersEstimate,
 *             excludeParameters: migrationInitialLoadSettingsDataPumpParametersExcludeParameters,
 *             exportParallelismDegree: migrationInitialLoadSettingsDataPumpParametersExportParallelismDegree,
 *             importParallelismDegree: migrationInitialLoadSettingsDataPumpParametersImportParallelismDegree,
 *             isCluster: migrationInitialLoadSettingsDataPumpParametersIsCluster,
 *             tableExistsAction: migrationInitialLoadSettingsDataPumpParametersTableExistsAction,
 *         },
 *         exportDirectoryObject: {
 *             name: migrationInitialLoadSettingsExportDirectoryObjectName,
 *             path: migrationInitialLoadSettingsExportDirectoryObjectPath,
 *         },
 *         handleGrantErrors: migrationInitialLoadSettingsHandleGrantErrors,
 *         importDirectoryObject: {
 *             name: migrationInitialLoadSettingsImportDirectoryObjectName,
 *             path: migrationInitialLoadSettingsImportDirectoryObjectPath,
 *         },
 *         isConsistent: migrationInitialLoadSettingsIsConsistent,
 *         isIgnoreExistingObjects: migrationInitialLoadSettingsIsIgnoreExistingObjects,
 *         isTzUtc: migrationInitialLoadSettingsIsTzUtc,
 *         metadataRemaps: [{
 *             newValue: migrationInitialLoadSettingsMetadataRemapsNewValue,
 *             oldValue: migrationInitialLoadSettingsMetadataRemapsOldValue,
 *             type: migrationInitialLoadSettingsMetadataRemapsType,
 *         }],
 *         primaryKeyCompatibility: migrationInitialLoadSettingsPrimaryKeyCompatibility,
 *         tablespaceDetails: {
 *             targetType: migrationInitialLoadSettingsTablespaceDetailsTargetType,
 *             blockSizeInKbs: migrationInitialLoadSettingsTablespaceDetailsBlockSizeInKbs,
 *             extendSizeInMbs: migrationInitialLoadSettingsTablespaceDetailsExtendSizeInMbs,
 *             isAutoCreate: migrationInitialLoadSettingsTablespaceDetailsIsAutoCreate,
 *             isBigFile: migrationInitialLoadSettingsTablespaceDetailsIsBigFile,
 *             remapTarget: migrationInitialLoadSettingsTablespaceDetailsRemapTarget,
 *         },
 *     },
 *     sourceContainerDatabaseConnectionId: testConnection.id,
 *     sourceStandbyDatabaseConnectionId: testConnection.id,
 * });
 * ```
 *
 * ## Import
 *
 * Migrations can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DatabaseMigration/migration:Migration test_migration "id"
 * ```
 */
export class Migration extends pulumi.CustomResource {
    /**
     * Get an existing Migration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MigrationState, opts?: pulumi.CustomResourceOptions): Migration {
        return new Migration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseMigration/migration:Migration';

    /**
     * Returns true if the given object is an instance of Migration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Migration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Migration.__pulumiType;
    }

    /**
     * (Updatable) List of Migration Parameter objects.
     */
    public readonly advancedParameters!: pulumi.Output<outputs.DatabaseMigration.MigrationAdvancedParameter[]>;
    /**
     * (Updatable) Optional Pre-Migration advisor settings.
     */
    public readonly advisorSettings!: pulumi.Output<outputs.DatabaseMigration.MigrationAdvisorSettings>;
    /**
     * Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
     */
    public readonly bulkIncludeExcludeData!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Optional additional properties for data transfer.
     */
    public readonly dataTransferMediumDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
     */
    public readonly databaseCombination!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly description. Does not have to be unique, and it's changeable.  Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable.  Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Database objects to exclude from migration, cannot be specified alongside 'includeObjects'
     */
    public readonly excludeObjects!: pulumi.Output<outputs.DatabaseMigration.MigrationExcludeObject[]>;
    /**
     * The OCID of the resource being referenced.
     */
    public /*out*/ readonly executingJobId!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Optional settings for Oracle GoldenGate processes
     */
    public readonly ggsDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationGgsDetails>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices.
     */
    public readonly hubDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationHubDetails>;
    /**
     * Database objects to include from migration, cannot be specified alongside 'excludeObjects'
     */
    public readonly includeObjects!: pulumi.Output<outputs.DatabaseMigration.MigrationIncludeObject[]>;
    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     */
    public readonly initialLoadSettings!: pulumi.Output<outputs.DatabaseMigration.MigrationInitialLoadSettings>;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    public readonly sourceContainerDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    public readonly sourceDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    public readonly sourceStandbyDatabaseConnectionId!: pulumi.Output<string | undefined>;
    /**
     * The current state of the Migration resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    public readonly targetDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     */
    public /*out*/ readonly timeLastMigration!: pulumi.Output<string>;
    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * You can optionally pause a migration after a job phase. This property allows you to optionally specify the phase after which you can pause the migration.
     */
    public /*out*/ readonly waitAfter!: pulumi.Output<string>;

    /**
     * Create a Migration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MigrationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MigrationArgs | MigrationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MigrationState | undefined;
            resourceInputs["advancedParameters"] = state ? state.advancedParameters : undefined;
            resourceInputs["advisorSettings"] = state ? state.advisorSettings : undefined;
            resourceInputs["bulkIncludeExcludeData"] = state ? state.bulkIncludeExcludeData : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dataTransferMediumDetails"] = state ? state.dataTransferMediumDetails : undefined;
            resourceInputs["databaseCombination"] = state ? state.databaseCombination : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["excludeObjects"] = state ? state.excludeObjects : undefined;
            resourceInputs["executingJobId"] = state ? state.executingJobId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["ggsDetails"] = state ? state.ggsDetails : undefined;
            resourceInputs["hubDetails"] = state ? state.hubDetails : undefined;
            resourceInputs["includeObjects"] = state ? state.includeObjects : undefined;
            resourceInputs["initialLoadSettings"] = state ? state.initialLoadSettings : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["sourceContainerDatabaseConnectionId"] = state ? state.sourceContainerDatabaseConnectionId : undefined;
            resourceInputs["sourceDatabaseConnectionId"] = state ? state.sourceDatabaseConnectionId : undefined;
            resourceInputs["sourceStandbyDatabaseConnectionId"] = state ? state.sourceStandbyDatabaseConnectionId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["targetDatabaseConnectionId"] = state ? state.targetDatabaseConnectionId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeLastMigration"] = state ? state.timeLastMigration : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["waitAfter"] = state ? state.waitAfter : undefined;
        } else {
            const args = argsOrState as MigrationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.databaseCombination === undefined) && !opts.urn) {
                throw new Error("Missing required property 'databaseCombination'");
            }
            if ((!args || args.sourceDatabaseConnectionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sourceDatabaseConnectionId'");
            }
            if ((!args || args.targetDatabaseConnectionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'targetDatabaseConnectionId'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["advancedParameters"] = args ? args.advancedParameters : undefined;
            resourceInputs["advisorSettings"] = args ? args.advisorSettings : undefined;
            resourceInputs["bulkIncludeExcludeData"] = args ? args.bulkIncludeExcludeData : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["dataTransferMediumDetails"] = args ? args.dataTransferMediumDetails : undefined;
            resourceInputs["databaseCombination"] = args ? args.databaseCombination : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["excludeObjects"] = args ? args.excludeObjects : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["ggsDetails"] = args ? args.ggsDetails : undefined;
            resourceInputs["hubDetails"] = args ? args.hubDetails : undefined;
            resourceInputs["includeObjects"] = args ? args.includeObjects : undefined;
            resourceInputs["initialLoadSettings"] = args ? args.initialLoadSettings : undefined;
            resourceInputs["sourceContainerDatabaseConnectionId"] = args ? args.sourceContainerDatabaseConnectionId : undefined;
            resourceInputs["sourceDatabaseConnectionId"] = args ? args.sourceDatabaseConnectionId : undefined;
            resourceInputs["sourceStandbyDatabaseConnectionId"] = args ? args.sourceStandbyDatabaseConnectionId : undefined;
            resourceInputs["targetDatabaseConnectionId"] = args ? args.targetDatabaseConnectionId : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["executingJobId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeLastMigration"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["waitAfter"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Migration.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Migration resources.
 */
export interface MigrationState {
    /**
     * (Updatable) List of Migration Parameter objects.
     */
    advancedParameters?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationAdvancedParameter>[]>;
    /**
     * (Updatable) Optional Pre-Migration advisor settings.
     */
    advisorSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationAdvisorSettings>;
    /**
     * Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
     */
    bulkIncludeExcludeData?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Optional additional properties for data transfer.
     */
    dataTransferMediumDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
     */
    databaseCombination?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. Does not have to be unique, and it's changeable.  Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable.  Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Database objects to exclude from migration, cannot be specified alongside 'includeObjects'
     */
    excludeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationExcludeObject>[]>;
    /**
     * The OCID of the resource being referenced.
     */
    executingJobId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Optional settings for Oracle GoldenGate processes
     */
    ggsDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationGgsDetails>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices.
     */
    hubDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationHubDetails>;
    /**
     * Database objects to include from migration, cannot be specified alongside 'excludeObjects'
     */
    includeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationIncludeObject>[]>;
    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     */
    initialLoadSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationInitialLoadSettings>;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    sourceContainerDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    sourceDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    sourceStandbyDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * The current state of the Migration resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    targetDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     */
    timeLastMigration?: pulumi.Input<string>;
    /**
     * An RFC3339 formatted datetime string such as `2016-08-25T21:10:29.600Z`.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type?: pulumi.Input<string>;
    /**
     * You can optionally pause a migration after a job phase. This property allows you to optionally specify the phase after which you can pause the migration.
     */
    waitAfter?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Migration resource.
 */
export interface MigrationArgs {
    /**
     * (Updatable) List of Migration Parameter objects.
     */
    advancedParameters?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationAdvancedParameter>[]>;
    /**
     * (Updatable) Optional Pre-Migration advisor settings.
     */
    advisorSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationAdvisorSettings>;
    /**
     * Specifies the database objects to be excluded from the migration in bulk. The definition accepts input in a CSV format, newline separated for each entry. More details can be found in the documentation.
     */
    bulkIncludeExcludeData?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Optional additional properties for data transfer.
     */
    dataTransferMediumDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) The combination of source and target databases participating in a migration. Example: ORACLE means the migration is meant for migrating Oracle source and target databases.
     */
    databaseCombination: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. Does not have to be unique, and it's changeable.  Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable.  Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Database objects to exclude from migration, cannot be specified alongside 'includeObjects'
     */
    excludeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationExcludeObject>[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Optional settings for Oracle GoldenGate processes
     */
    ggsDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationGgsDetails>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices.
     */
    hubDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationHubDetails>;
    /**
     * Database objects to include from migration, cannot be specified alongside 'excludeObjects'
     */
    includeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationIncludeObject>[]>;
    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     */
    initialLoadSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationInitialLoadSettings>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    sourceContainerDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    sourceDatabaseConnectionId: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    sourceStandbyDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the resource being referenced.
     */
    targetDatabaseConnectionId: pulumi.Input<string>;
    /**
     * (Updatable) The type of the migration to be performed. Example: ONLINE if no downtime is preferred for a migration. This method uses Oracle GoldenGate for replication.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    type: pulumi.Input<string>;
}
