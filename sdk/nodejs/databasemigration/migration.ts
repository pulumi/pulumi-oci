// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Migration resource in Oracle Cloud Infrastructure Database Migration service.
 *
 * Create a Migration resource that contains all the details to perform the
 * database migration operation, such as source and destination database
 * details, credentials, etc.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMigration = new oci.databasemigration.Migration("testMigration", {
 *     compartmentId: _var.compartment_id,
 *     sourceDatabaseConnectionId: oci_database_migration_connection.test_connection.id,
 *     targetDatabaseConnectionId: oci_database_migration_connection.test_connection.id,
 *     type: _var.migration_type,
 *     advisorSettings: {
 *         isIgnoreErrors: _var.migration_advisor_settings_is_ignore_errors,
 *         isSkipAdvisor: _var.migration_advisor_settings_is_skip_advisor,
 *     },
 *     agentId: oci_database_migration_agent.test_agent.id,
 *     dataTransferMediumDetails: {
 *         databaseLinkDetails: {
 *             name: _var.migration_data_transfer_medium_details_database_link_details_name,
 *             walletBucket: {
 *                 bucket: _var.migration_data_transfer_medium_details_database_link_details_wallet_bucket_bucket,
 *                 namespace: _var.migration_data_transfer_medium_details_database_link_details_wallet_bucket_namespace,
 *             },
 *         },
 *         objectStorageDetails: {
 *             bucket: _var.migration_data_transfer_medium_details_object_storage_details_bucket,
 *             namespace: _var.migration_data_transfer_medium_details_object_storage_details_namespace,
 *         },
 *     },
 *     datapumpSettings: {
 *         dataPumpParameters: {
 *             estimate: _var.migration_datapump_settings_data_pump_parameters_estimate,
 *             excludeParameters: _var.migration_datapump_settings_data_pump_parameters_exclude_parameters,
 *             exportParallelismDegree: _var.migration_datapump_settings_data_pump_parameters_export_parallelism_degree,
 *             importParallelismDegree: _var.migration_datapump_settings_data_pump_parameters_import_parallelism_degree,
 *             isCluster: _var.migration_datapump_settings_data_pump_parameters_is_cluster,
 *             tableExistsAction: _var.migration_datapump_settings_data_pump_parameters_table_exists_action,
 *         },
 *         exportDirectoryObject: {
 *             name: _var.migration_datapump_settings_export_directory_object_name,
 *             path: _var.migration_datapump_settings_export_directory_object_path,
 *         },
 *         importDirectoryObject: {
 *             name: _var.migration_datapump_settings_import_directory_object_name,
 *             path: _var.migration_datapump_settings_import_directory_object_path,
 *         },
 *         jobMode: _var.migration_datapump_settings_job_mode,
 *         metadataRemaps: [{
 *             newValue: _var.migration_datapump_settings_metadata_remaps_new_value,
 *             oldValue: _var.migration_datapump_settings_metadata_remaps_old_value,
 *             type: _var.migration_datapump_settings_metadata_remaps_type,
 *         }],
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: _var.migration_display_name,
 *     dumpTransferDetails: {
 *         source: {
 *             kind: _var.migration_dump_transfer_details_source_kind,
 *             ociHome: _var.migration_dump_transfer_details_source_oci_home,
 *         },
 *         target: {
 *             kind: _var.migration_dump_transfer_details_target_kind,
 *             ociHome: _var.migration_dump_transfer_details_target_oci_home,
 *         },
 *     },
 *     excludeObjects: [{
 *         object: _var.migration_exclude_objects_object,
 *         owner: _var.migration_exclude_objects_owner,
 *         type: _var.migration_exclude_objects_type,
 *     }],
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     goldenGateDetails: {
 *         hub: {
 *             restAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_rest_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_rest_admin_credentials_username,
 *             },
 *             sourceDbAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_source_db_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_source_db_admin_credentials_username,
 *             },
 *             sourceMicroservicesDeploymentName: oci_apigateway_deployment.test_deployment.name,
 *             targetDbAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_target_db_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_target_db_admin_credentials_username,
 *             },
 *             targetMicroservicesDeploymentName: oci_apigateway_deployment.test_deployment.name,
 *             url: _var.migration_golden_gate_details_hub_url,
 *             computeId: oci_database_migration_compute.test_compute.id,
 *             sourceContainerDbAdminCredentials: {
 *                 password: _var.migration_golden_gate_details_hub_source_container_db_admin_credentials_password,
 *                 username: _var.migration_golden_gate_details_hub_source_container_db_admin_credentials_username,
 *             },
 *         },
 *         settings: {
 *             acceptableLag: _var.migration_golden_gate_details_settings_acceptable_lag,
 *             extract: {
 *                 longTransDuration: _var.migration_golden_gate_details_settings_extract_long_trans_duration,
 *                 performanceProfile: _var.migration_golden_gate_details_settings_extract_performance_profile,
 *             },
 *             replicat: {
 *                 mapParallelism: _var.migration_golden_gate_details_settings_replicat_map_parallelism,
 *                 maxApplyParallelism: _var.migration_golden_gate_details_settings_replicat_max_apply_parallelism,
 *                 minApplyParallelism: _var.migration_golden_gate_details_settings_replicat_min_apply_parallelism,
 *             },
 *         },
 *     },
 *     includeObjects: [{
 *         object: _var.migration_include_objects_object,
 *         owner: _var.migration_include_objects_owner,
 *         type: _var.migration_include_objects_type,
 *     }],
 *     sourceContainerDatabaseConnectionId: oci_database_migration_connection.test_connection.id,
 *     vaultDetails: {
 *         compartmentId: _var.compartment_id,
 *         keyId: oci_kms_key.test_key.id,
 *         vaultId: oci_kms_vault.test_vault.id,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Migrations can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DatabaseMigration/migration:Migration test_migration "id"
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
     * (Updatable) Optional Pre-Migration advisor settings.
     */
    public readonly advisorSettings!: pulumi.Output<outputs.DatabaseMigration.MigrationAdvisorSettings>;
    /**
     * (Updatable) The OCID of the registered ODMS Agent. Only valid for Offline Logical Migrations.
     */
    public readonly agentId!: pulumi.Output<string>;
    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store GoldenGate administrator user credentials.
     */
    public /*out*/ readonly credentialsSecretId!: pulumi.Output<string>;
    /**
     * (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of data transfer medium can be specified.
     */
    public readonly dataTransferMediumDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     */
    public readonly datapumpSettings!: pulumi.Output<outputs.DatabaseMigration.MigrationDatapumpSettings>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Migration Display Name
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Optional additional properties for dump transfer.
     */
    public readonly dumpTransferDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationDumpTransferDetails>;
    /**
     * (Updatable) Database objects to exclude from migration, cannot be specified alongside 'includeObjects'
     */
    public readonly excludeObjects!: pulumi.Output<outputs.DatabaseMigration.MigrationExcludeObject[]>;
    /**
     * OCID of the current ODMS Job in execution for the Migration, if any.
     */
    public /*out*/ readonly executingJobId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     */
    public readonly goldenGateDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationGoldenGateDetails>;
    /**
     * (Updatable) Database objects to include from migration, cannot be specified alongside 'excludeObjects'
     */
    public readonly includeObjects!: pulumi.Output<outputs.DatabaseMigration.MigrationIncludeObject[]>;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the Source Container Database Connection. Only used for Online migrations. Only Connections of type Non-Autonomous can be used as source container databases.
     */
    public readonly sourceContainerDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the Source Database Connection.
     */
    public readonly sourceDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * The current state of the Migration resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The OCID of the Target Database Connection.
     */
    public readonly targetDatabaseConnectionId!: pulumi.Output<string>;
    /**
     * The time the Migration was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time of last Migration. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeLastMigration!: pulumi.Output<string>;
    /**
     * The time of the last Migration details update. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) Migration type.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     */
    public readonly vaultDetails!: pulumi.Output<outputs.DatabaseMigration.MigrationVaultDetails>;
    /**
     * Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
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
            resourceInputs["advisorSettings"] = state ? state.advisorSettings : undefined;
            resourceInputs["agentId"] = state ? state.agentId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["credentialsSecretId"] = state ? state.credentialsSecretId : undefined;
            resourceInputs["dataTransferMediumDetails"] = state ? state.dataTransferMediumDetails : undefined;
            resourceInputs["datapumpSettings"] = state ? state.datapumpSettings : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["dumpTransferDetails"] = state ? state.dumpTransferDetails : undefined;
            resourceInputs["excludeObjects"] = state ? state.excludeObjects : undefined;
            resourceInputs["executingJobId"] = state ? state.executingJobId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["goldenGateDetails"] = state ? state.goldenGateDetails : undefined;
            resourceInputs["includeObjects"] = state ? state.includeObjects : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["sourceContainerDatabaseConnectionId"] = state ? state.sourceContainerDatabaseConnectionId : undefined;
            resourceInputs["sourceDatabaseConnectionId"] = state ? state.sourceDatabaseConnectionId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["targetDatabaseConnectionId"] = state ? state.targetDatabaseConnectionId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeLastMigration"] = state ? state.timeLastMigration : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["vaultDetails"] = state ? state.vaultDetails : undefined;
            resourceInputs["waitAfter"] = state ? state.waitAfter : undefined;
        } else {
            const args = argsOrState as MigrationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
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
            resourceInputs["advisorSettings"] = args ? args.advisorSettings : undefined;
            resourceInputs["agentId"] = args ? args.agentId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["dataTransferMediumDetails"] = args ? args.dataTransferMediumDetails : undefined;
            resourceInputs["datapumpSettings"] = args ? args.datapumpSettings : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["dumpTransferDetails"] = args ? args.dumpTransferDetails : undefined;
            resourceInputs["excludeObjects"] = args ? args.excludeObjects : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["goldenGateDetails"] = args ? args.goldenGateDetails : undefined;
            resourceInputs["includeObjects"] = args ? args.includeObjects : undefined;
            resourceInputs["sourceContainerDatabaseConnectionId"] = args ? args.sourceContainerDatabaseConnectionId : undefined;
            resourceInputs["sourceDatabaseConnectionId"] = args ? args.sourceDatabaseConnectionId : undefined;
            resourceInputs["targetDatabaseConnectionId"] = args ? args.targetDatabaseConnectionId : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["vaultDetails"] = args ? args.vaultDetails : undefined;
            resourceInputs["credentialsSecretId"] = undefined /*out*/;
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
     * (Updatable) Optional Pre-Migration advisor settings.
     */
    advisorSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationAdvisorSettings>;
    /**
     * (Updatable) The OCID of the registered ODMS Agent. Only valid for Offline Logical Migrations.
     */
    agentId?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store GoldenGate administrator user credentials.
     */
    credentialsSecretId?: pulumi.Input<string>;
    /**
     * (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of data transfer medium can be specified.
     */
    dataTransferMediumDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     */
    datapumpSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationDatapumpSettings>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Migration Display Name
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Optional additional properties for dump transfer.
     */
    dumpTransferDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationDumpTransferDetails>;
    /**
     * (Updatable) Database objects to exclude from migration, cannot be specified alongside 'includeObjects'
     */
    excludeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationExcludeObject>[]>;
    /**
     * OCID of the current ODMS Job in execution for the Migration, if any.
     */
    executingJobId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     */
    goldenGateDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationGoldenGateDetails>;
    /**
     * (Updatable) Database objects to include from migration, cannot be specified alongside 'excludeObjects'
     */
    includeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationIncludeObject>[]>;
    /**
     * Additional status related to the execution and current state of the Migration.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Source Container Database Connection. Only used for Online migrations. Only Connections of type Non-Autonomous can be used as source container databases.
     */
    sourceContainerDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Source Database Connection.
     */
    sourceDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * The current state of the Migration resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The OCID of the Target Database Connection.
     */
    targetDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * The time the Migration was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time of last Migration. An RFC3339 formatted datetime string.
     */
    timeLastMigration?: pulumi.Input<string>;
    /**
     * The time of the last Migration details update. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) Migration type.
     */
    type?: pulumi.Input<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     */
    vaultDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationVaultDetails>;
    /**
     * Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
     */
    waitAfter?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Migration resource.
 */
export interface MigrationArgs {
    /**
     * (Updatable) Optional Pre-Migration advisor settings.
     */
    advisorSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationAdvisorSettings>;
    /**
     * (Updatable) The OCID of the registered ODMS Agent. Only valid for Offline Logical Migrations.
     */
    agentId?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of data transfer medium can be specified.
     */
    dataTransferMediumDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationDataTransferMediumDetails>;
    /**
     * (Updatable) Optional settings for Data Pump Export and Import jobs
     */
    datapumpSettings?: pulumi.Input<inputs.DatabaseMigration.MigrationDatapumpSettings>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Migration Display Name
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Optional additional properties for dump transfer.
     */
    dumpTransferDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationDumpTransferDetails>;
    /**
     * (Updatable) Database objects to exclude from migration, cannot be specified alongside 'includeObjects'
     */
    excludeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationExcludeObject>[]>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     */
    goldenGateDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationGoldenGateDetails>;
    /**
     * (Updatable) Database objects to include from migration, cannot be specified alongside 'excludeObjects'
     */
    includeObjects?: pulumi.Input<pulumi.Input<inputs.DatabaseMigration.MigrationIncludeObject>[]>;
    /**
     * (Updatable) The OCID of the Source Container Database Connection. Only used for Online migrations. Only Connections of type Non-Autonomous can be used as source container databases.
     */
    sourceContainerDatabaseConnectionId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Source Database Connection.
     */
    sourceDatabaseConnectionId: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Target Database Connection.
     */
    targetDatabaseConnectionId: pulumi.Input<string>;
    /**
     * (Updatable) Migration type.
     */
    type: pulumi.Input<string>;
    /**
     * (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
     */
    vaultDetails?: pulumi.Input<inputs.DatabaseMigration.MigrationVaultDetails>;
}