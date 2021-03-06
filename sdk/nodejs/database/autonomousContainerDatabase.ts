// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Autonomous Container Database resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates an Autonomous Container Database in the specified Autonomous Exadata Infrastructure.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousContainerDatabase = new oci.database.AutonomousContainerDatabase("testAutonomousContainerDatabase", {
 *     displayName: _var.autonomous_container_database_display_name,
 *     patchModel: _var.autonomous_container_database_patch_model,
 *     cloudAutonomousVmClusterId: oci_database_cloud_autonomous_vm_cluster.test_cloud_autonomous_vm_cluster.id,
 *     autonomousVmClusterId: oci_database_autonomous_vm_cluster.test_autonomous_vm_cluster.id,
 *     backupConfig: {
 *         backupDestinationDetails: {
 *             type: _var.autonomous_container_database_backup_config_backup_destination_details_type,
 *             id: _var.autonomous_container_database_backup_config_backup_destination_details_id,
 *             internetProxy: _var.autonomous_container_database_backup_config_backup_destination_details_internet_proxy,
 *             vpcPassword: _var.autonomous_container_database_backup_config_backup_destination_details_vpc_password,
 *             vpcUser: _var.autonomous_container_database_backup_config_backup_destination_details_vpc_user,
 *         },
 *         recoveryWindowInDays: _var.autonomous_container_database_backup_config_recovery_window_in_days,
 *     },
 *     compartmentId: _var.compartment_id,
 *     dbUniqueName: _var.autonomous_container_database_db_unique_name,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isAutomaticFailoverEnabled: _var.autonomous_container_database_is_automatic_failover_enabled,
 *     keyStoreId: oci_database_key_store.test_key_store.id,
 *     kmsKeyId: oci_kms_key.test_key.id,
 *     maintenanceWindowDetails: {
 *         preference: _var.autonomous_container_database_maintenance_window_details_preference,
 *         customActionTimeoutInMins: _var.autonomous_container_database_maintenance_window_details_custom_action_timeout_in_mins,
 *         daysOfWeeks: [{
 *             name: _var.autonomous_container_database_maintenance_window_details_days_of_week_name,
 *         }],
 *         hoursOfDays: _var.autonomous_container_database_maintenance_window_details_hours_of_day,
 *         isCustomActionTimeoutEnabled: _var.autonomous_container_database_maintenance_window_details_is_custom_action_timeout_enabled,
 *         leadTimeInWeeks: _var.autonomous_container_database_maintenance_window_details_lead_time_in_weeks,
 *         months: [{
 *             name: _var.autonomous_container_database_maintenance_window_details_months_name,
 *         }],
 *         patchingMode: _var.autonomous_container_database_maintenance_window_details_patching_mode,
 *         weeksOfMonths: _var.autonomous_container_database_maintenance_window_details_weeks_of_month,
 *     },
 *     peerAutonomousContainerDatabaseDisplayName: _var.autonomous_container_database_peer_autonomous_container_database_display_name,
 *     peerCloudAutonomousVmClusterId: oci_database_cloud_autonomous_vm_cluster.test_cloud_autonomous_vm_cluster.id,
 *     protectionMode: _var.autonomous_container_database_protection_mode,
 *     peerAutonomousContainerDatabaseBackupConfig: {
 *         backupDestinationDetails: [{
 *             type: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_type,
 *             id: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_id,
 *             internetProxy: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_internet_proxy,
 *             vpcPassword: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_vpc_password,
 *             vpcUser: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_backup_destination_details_vpc_user,
 *         }],
 *         recoveryWindowInDays: _var.autonomous_container_database_peer_autonomous_container_database_backup_config_recovery_window_in_days,
 *     },
 *     peerAutonomousContainerDatabaseCompartmentId: oci_identity_compartment.test_compartment.id,
 *     peerAutonomousVmClusterId: oci_database_autonomous_vm_cluster.test_autonomous_vm_cluster.id,
 *     peerDbUniqueName: _var.autonomous_container_database_peer_db_unique_name,
 *     serviceLevelAgreementType: _var.autonomous_container_database_service_level_agreement_type,
 *     vaultId: oci_kms_vault.test_vault.id,
 *     standbyMaintenanceBufferInDays: _var.autonomous_container_database_standby_maintenance_buffer_in_days,
 * });
 * ```
 *
 * ## Import
 *
 * AutonomousContainerDatabases can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Database/autonomousContainerDatabase:AutonomousContainerDatabase test_autonomous_container_database "id"
 * ```
 */
export class AutonomousContainerDatabase extends pulumi.CustomResource {
    /**
     * Get an existing AutonomousContainerDatabase resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutonomousContainerDatabaseState, opts?: pulumi.CustomResourceOptions): AutonomousContainerDatabase {
        return new AutonomousContainerDatabase(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/autonomousContainerDatabase:AutonomousContainerDatabase';

    /**
     * Returns true if the given object is an instance of AutonomousContainerDatabase.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutonomousContainerDatabase {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutonomousContainerDatabase.__pulumiType;
    }

    /**
     * The OCID of the Autonomous Exadata Infrastructure. Please use cloudAutonomousVmClusterId instead.
     */
    public readonly autonomousExadataInfrastructureId!: pulumi.Output<string>;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    public readonly autonomousVmClusterId!: pulumi.Output<string>;
    /**
     * The availability domain of the Autonomous Container Database.
     */
    public /*out*/ readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) Backup options for the Autonomous Container Database.
     */
    public readonly backupConfig!: pulumi.Output<outputs.Database.AutonomousContainerDatabaseBackupConfig>;
    /**
     * The OCID of the Cloud Autonomous VM Cluster.
     */
    public readonly cloudAutonomousVmClusterId!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Autonomous Container Database.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    public readonly dbUniqueName!: pulumi.Output<string>;
    /**
     * Oracle Database version of the Autonomous Container Database.
     */
    public /*out*/ readonly dbVersion!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The display name for the Autonomous Container Database.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The infrastructure type this resource belongs to.
     */
    public /*out*/ readonly infrastructureType!: pulumi.Output<string>;
    /**
     * Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
     */
    public readonly isAutomaticFailoverEnabled!: pulumi.Output<boolean>;
    /**
     * Key History Entry.
     */
    public /*out*/ readonly keyHistoryEntries!: pulumi.Output<outputs.Database.AutonomousContainerDatabaseKeyHistoryEntry[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    public readonly keyStoreId!: pulumi.Output<string>;
    /**
     * The wallet name for Oracle Key Vault.
     */
    public /*out*/ readonly keyStoreWalletName!: pulumi.Output<string>;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    public readonly kmsKeyId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    public /*out*/ readonly lastMaintenanceRunId!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    public readonly maintenanceWindowDetails!: pulumi.Output<outputs.Database.AutonomousContainerDatabaseMaintenanceWindowDetails | undefined>;
    /**
     * The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    public /*out*/ readonly maintenanceWindows!: pulumi.Output<outputs.Database.AutonomousContainerDatabaseMaintenanceWindow[]>;
    /**
     * The amount of memory (in GBs) enabled per each OCPU core in Autonomous VM Cluster.
     */
    public /*out*/ readonly memoryPerOracleComputeUnitInGbs!: pulumi.Output<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    public /*out*/ readonly nextMaintenanceRunId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
     */
    public /*out*/ readonly patchId!: pulumi.Output<string>;
    /**
     * (Updatable) Database Patch model preference.
     */
    public readonly patchModel!: pulumi.Output<string>;
    public readonly peerAutonomousContainerDatabaseBackupConfig!: pulumi.Output<outputs.Database.AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the standby Autonomous Container Database will be created.
     */
    public readonly peerAutonomousContainerDatabaseCompartmentId!: pulumi.Output<string>;
    /**
     * The display name for the peer Autonomous Container Database.
     */
    public readonly peerAutonomousContainerDatabaseDisplayName!: pulumi.Output<string>;
    /**
     * The OCID of the peer Autonomous Exadata Infrastructure for autonomous dataguard. Please use peerCloudAutonomousVmClusterId instead.
     */
    public readonly peerAutonomousExadataInfrastructureId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous VM cluster for Autonomous Data Guard. Required to enable Data Guard.
     */
    public readonly peerAutonomousVmClusterId!: pulumi.Output<string>;
    /**
     * The OCID of the peer Autonomous Cloud VM Cluster for autonomous dataguard.
     */
    public readonly peerCloudAutonomousVmClusterId!: pulumi.Output<string>;
    public readonly peerDbUniqueName!: pulumi.Output<string>;
    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    public readonly protectionMode!: pulumi.Output<string>;
    /**
     * The role of the dataguard enabled Autonomous Container Database.
     */
    public /*out*/ readonly role!: pulumi.Output<string>;
    /**
     * (Updatable) An optional property when flipped triggers rotation of KMS key. It is only applicable on dedicated container databases i.e. where `cloudAutonomousVmClusterId` is set.
     */
    public readonly rotateKeyTrigger!: pulumi.Output<boolean | undefined>;
    /**
     * The service level agreement type of the Autonomous Container Database. The default is STANDARD. For an autonomous dataguard Autonomous Container Database, the specified Autonomous Exadata Infrastructure must be associated with a remote Autonomous Exadata Infrastructure.
     */
    public readonly serviceLevelAgreementType!: pulumi.Output<string>;
    /**
     * (Updatable) The scheduling detail for the quarterly maintenance window of standby Autonomous Container Database. This value represents the number of days before the primary database maintenance schedule.
     */
    public readonly standbyMaintenanceBufferInDays!: pulumi.Output<number>;
    /**
     * The current state of the Autonomous Container Database.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the Autonomous Container Database was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    public readonly vaultId!: pulumi.Output<string>;

    /**
     * Create a AutonomousContainerDatabase resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AutonomousContainerDatabaseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutonomousContainerDatabaseArgs | AutonomousContainerDatabaseState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutonomousContainerDatabaseState | undefined;
            resourceInputs["autonomousExadataInfrastructureId"] = state ? state.autonomousExadataInfrastructureId : undefined;
            resourceInputs["autonomousVmClusterId"] = state ? state.autonomousVmClusterId : undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["backupConfig"] = state ? state.backupConfig : undefined;
            resourceInputs["cloudAutonomousVmClusterId"] = state ? state.cloudAutonomousVmClusterId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dbUniqueName"] = state ? state.dbUniqueName : undefined;
            resourceInputs["dbVersion"] = state ? state.dbVersion : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["infrastructureType"] = state ? state.infrastructureType : undefined;
            resourceInputs["isAutomaticFailoverEnabled"] = state ? state.isAutomaticFailoverEnabled : undefined;
            resourceInputs["keyHistoryEntries"] = state ? state.keyHistoryEntries : undefined;
            resourceInputs["keyStoreId"] = state ? state.keyStoreId : undefined;
            resourceInputs["keyStoreWalletName"] = state ? state.keyStoreWalletName : undefined;
            resourceInputs["kmsKeyId"] = state ? state.kmsKeyId : undefined;
            resourceInputs["lastMaintenanceRunId"] = state ? state.lastMaintenanceRunId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["maintenanceWindowDetails"] = state ? state.maintenanceWindowDetails : undefined;
            resourceInputs["maintenanceWindows"] = state ? state.maintenanceWindows : undefined;
            resourceInputs["memoryPerOracleComputeUnitInGbs"] = state ? state.memoryPerOracleComputeUnitInGbs : undefined;
            resourceInputs["nextMaintenanceRunId"] = state ? state.nextMaintenanceRunId : undefined;
            resourceInputs["patchId"] = state ? state.patchId : undefined;
            resourceInputs["patchModel"] = state ? state.patchModel : undefined;
            resourceInputs["peerAutonomousContainerDatabaseBackupConfig"] = state ? state.peerAutonomousContainerDatabaseBackupConfig : undefined;
            resourceInputs["peerAutonomousContainerDatabaseCompartmentId"] = state ? state.peerAutonomousContainerDatabaseCompartmentId : undefined;
            resourceInputs["peerAutonomousContainerDatabaseDisplayName"] = state ? state.peerAutonomousContainerDatabaseDisplayName : undefined;
            resourceInputs["peerAutonomousExadataInfrastructureId"] = state ? state.peerAutonomousExadataInfrastructureId : undefined;
            resourceInputs["peerAutonomousVmClusterId"] = state ? state.peerAutonomousVmClusterId : undefined;
            resourceInputs["peerCloudAutonomousVmClusterId"] = state ? state.peerCloudAutonomousVmClusterId : undefined;
            resourceInputs["peerDbUniqueName"] = state ? state.peerDbUniqueName : undefined;
            resourceInputs["protectionMode"] = state ? state.protectionMode : undefined;
            resourceInputs["role"] = state ? state.role : undefined;
            resourceInputs["rotateKeyTrigger"] = state ? state.rotateKeyTrigger : undefined;
            resourceInputs["serviceLevelAgreementType"] = state ? state.serviceLevelAgreementType : undefined;
            resourceInputs["standbyMaintenanceBufferInDays"] = state ? state.standbyMaintenanceBufferInDays : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["vaultId"] = state ? state.vaultId : undefined;
        } else {
            const args = argsOrState as AutonomousContainerDatabaseArgs | undefined;
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.patchModel === undefined) && !opts.urn) {
                throw new Error("Missing required property 'patchModel'");
            }
            resourceInputs["autonomousExadataInfrastructureId"] = args ? args.autonomousExadataInfrastructureId : undefined;
            resourceInputs["autonomousVmClusterId"] = args ? args.autonomousVmClusterId : undefined;
            resourceInputs["backupConfig"] = args ? args.backupConfig : undefined;
            resourceInputs["cloudAutonomousVmClusterId"] = args ? args.cloudAutonomousVmClusterId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["dbUniqueName"] = args ? args.dbUniqueName : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isAutomaticFailoverEnabled"] = args ? args.isAutomaticFailoverEnabled : undefined;
            resourceInputs["keyStoreId"] = args ? args.keyStoreId : undefined;
            resourceInputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            resourceInputs["maintenanceWindowDetails"] = args ? args.maintenanceWindowDetails : undefined;
            resourceInputs["patchModel"] = args ? args.patchModel : undefined;
            resourceInputs["peerAutonomousContainerDatabaseBackupConfig"] = args ? args.peerAutonomousContainerDatabaseBackupConfig : undefined;
            resourceInputs["peerAutonomousContainerDatabaseCompartmentId"] = args ? args.peerAutonomousContainerDatabaseCompartmentId : undefined;
            resourceInputs["peerAutonomousContainerDatabaseDisplayName"] = args ? args.peerAutonomousContainerDatabaseDisplayName : undefined;
            resourceInputs["peerAutonomousExadataInfrastructureId"] = args ? args.peerAutonomousExadataInfrastructureId : undefined;
            resourceInputs["peerAutonomousVmClusterId"] = args ? args.peerAutonomousVmClusterId : undefined;
            resourceInputs["peerCloudAutonomousVmClusterId"] = args ? args.peerCloudAutonomousVmClusterId : undefined;
            resourceInputs["peerDbUniqueName"] = args ? args.peerDbUniqueName : undefined;
            resourceInputs["protectionMode"] = args ? args.protectionMode : undefined;
            resourceInputs["rotateKeyTrigger"] = args ? args.rotateKeyTrigger : undefined;
            resourceInputs["serviceLevelAgreementType"] = args ? args.serviceLevelAgreementType : undefined;
            resourceInputs["standbyMaintenanceBufferInDays"] = args ? args.standbyMaintenanceBufferInDays : undefined;
            resourceInputs["vaultId"] = args ? args.vaultId : undefined;
            resourceInputs["availabilityDomain"] = undefined /*out*/;
            resourceInputs["dbVersion"] = undefined /*out*/;
            resourceInputs["infrastructureType"] = undefined /*out*/;
            resourceInputs["keyHistoryEntries"] = undefined /*out*/;
            resourceInputs["keyStoreWalletName"] = undefined /*out*/;
            resourceInputs["lastMaintenanceRunId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["maintenanceWindows"] = undefined /*out*/;
            resourceInputs["memoryPerOracleComputeUnitInGbs"] = undefined /*out*/;
            resourceInputs["nextMaintenanceRunId"] = undefined /*out*/;
            resourceInputs["patchId"] = undefined /*out*/;
            resourceInputs["role"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AutonomousContainerDatabase.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutonomousContainerDatabase resources.
 */
export interface AutonomousContainerDatabaseState {
    /**
     * The OCID of the Autonomous Exadata Infrastructure. Please use cloudAutonomousVmClusterId instead.
     */
    autonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    autonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The availability domain of the Autonomous Container Database.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Backup options for the Autonomous Container Database.
     */
    backupConfig?: pulumi.Input<inputs.Database.AutonomousContainerDatabaseBackupConfig>;
    /**
     * The OCID of the Cloud Autonomous VM Cluster.
     */
    cloudAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Autonomous Container Database.
     */
    compartmentId?: pulumi.Input<string>;
    dbUniqueName?: pulumi.Input<string>;
    /**
     * Oracle Database version of the Autonomous Container Database.
     */
    dbVersion?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The display name for the Autonomous Container Database.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The infrastructure type this resource belongs to.
     */
    infrastructureType?: pulumi.Input<string>;
    /**
     * Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
     */
    isAutomaticFailoverEnabled?: pulumi.Input<boolean>;
    /**
     * Key History Entry.
     */
    keyHistoryEntries?: pulumi.Input<pulumi.Input<inputs.Database.AutonomousContainerDatabaseKeyHistoryEntry>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    keyStoreId?: pulumi.Input<string>;
    /**
     * The wallet name for Oracle Key Vault.
     */
    keyStoreWalletName?: pulumi.Input<string>;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    lastMaintenanceRunId?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    maintenanceWindowDetails?: pulumi.Input<inputs.Database.AutonomousContainerDatabaseMaintenanceWindowDetails>;
    /**
     * The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    maintenanceWindows?: pulumi.Input<pulumi.Input<inputs.Database.AutonomousContainerDatabaseMaintenanceWindow>[]>;
    /**
     * The amount of memory (in GBs) enabled per each OCPU core in Autonomous VM Cluster.
     */
    memoryPerOracleComputeUnitInGbs?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    nextMaintenanceRunId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
     */
    patchId?: pulumi.Input<string>;
    /**
     * (Updatable) Database Patch model preference.
     */
    patchModel?: pulumi.Input<string>;
    peerAutonomousContainerDatabaseBackupConfig?: pulumi.Input<inputs.Database.AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the standby Autonomous Container Database will be created.
     */
    peerAutonomousContainerDatabaseCompartmentId?: pulumi.Input<string>;
    /**
     * The display name for the peer Autonomous Container Database.
     */
    peerAutonomousContainerDatabaseDisplayName?: pulumi.Input<string>;
    /**
     * The OCID of the peer Autonomous Exadata Infrastructure for autonomous dataguard. Please use peerCloudAutonomousVmClusterId instead.
     */
    peerAutonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous VM cluster for Autonomous Data Guard. Required to enable Data Guard.
     */
    peerAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The OCID of the peer Autonomous Cloud VM Cluster for autonomous dataguard.
     */
    peerCloudAutonomousVmClusterId?: pulumi.Input<string>;
    peerDbUniqueName?: pulumi.Input<string>;
    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    protectionMode?: pulumi.Input<string>;
    /**
     * The role of the dataguard enabled Autonomous Container Database.
     */
    role?: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when flipped triggers rotation of KMS key. It is only applicable on dedicated container databases i.e. where `cloudAutonomousVmClusterId` is set.
     */
    rotateKeyTrigger?: pulumi.Input<boolean>;
    /**
     * The service level agreement type of the Autonomous Container Database. The default is STANDARD. For an autonomous dataguard Autonomous Container Database, the specified Autonomous Exadata Infrastructure must be associated with a remote Autonomous Exadata Infrastructure.
     */
    serviceLevelAgreementType?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling detail for the quarterly maintenance window of standby Autonomous Container Database. This value represents the number of days before the primary database maintenance schedule.
     */
    standbyMaintenanceBufferInDays?: pulumi.Input<number>;
    /**
     * The current state of the Autonomous Container Database.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the Autonomous Container Database was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    vaultId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutonomousContainerDatabase resource.
 */
export interface AutonomousContainerDatabaseArgs {
    /**
     * The OCID of the Autonomous Exadata Infrastructure. Please use cloudAutonomousVmClusterId instead.
     */
    autonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    autonomousVmClusterId?: pulumi.Input<string>;
    /**
     * (Updatable) Backup options for the Autonomous Container Database.
     */
    backupConfig?: pulumi.Input<inputs.Database.AutonomousContainerDatabaseBackupConfig>;
    /**
     * The OCID of the Cloud Autonomous VM Cluster.
     */
    cloudAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Autonomous Container Database.
     */
    compartmentId?: pulumi.Input<string>;
    dbUniqueName?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The display name for the Autonomous Container Database.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
     */
    isAutomaticFailoverEnabled?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    keyStoreId?: pulumi.Input<string>;
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    maintenanceWindowDetails?: pulumi.Input<inputs.Database.AutonomousContainerDatabaseMaintenanceWindowDetails>;
    /**
     * (Updatable) Database Patch model preference.
     */
    patchModel: pulumi.Input<string>;
    peerAutonomousContainerDatabaseBackupConfig?: pulumi.Input<inputs.Database.AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the standby Autonomous Container Database will be created.
     */
    peerAutonomousContainerDatabaseCompartmentId?: pulumi.Input<string>;
    /**
     * The display name for the peer Autonomous Container Database.
     */
    peerAutonomousContainerDatabaseDisplayName?: pulumi.Input<string>;
    /**
     * The OCID of the peer Autonomous Exadata Infrastructure for autonomous dataguard. Please use peerCloudAutonomousVmClusterId instead.
     */
    peerAutonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous VM cluster for Autonomous Data Guard. Required to enable Data Guard.
     */
    peerAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The OCID of the peer Autonomous Cloud VM Cluster for autonomous dataguard.
     */
    peerCloudAutonomousVmClusterId?: pulumi.Input<string>;
    peerDbUniqueName?: pulumi.Input<string>;
    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    protectionMode?: pulumi.Input<string>;
    /**
     * (Updatable) An optional property when flipped triggers rotation of KMS key. It is only applicable on dedicated container databases i.e. where `cloudAutonomousVmClusterId` is set.
     */
    rotateKeyTrigger?: pulumi.Input<boolean>;
    /**
     * The service level agreement type of the Autonomous Container Database. The default is STANDARD. For an autonomous dataguard Autonomous Container Database, the specified Autonomous Exadata Infrastructure must be associated with a remote Autonomous Exadata Infrastructure.
     */
    serviceLevelAgreementType?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduling detail for the quarterly maintenance window of standby Autonomous Container Database. This value represents the number of days before the primary database maintenance schedule.
     */
    standbyMaintenanceBufferInDays?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     */
    vaultId?: pulumi.Input<string>;
}
