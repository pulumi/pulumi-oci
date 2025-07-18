// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Autonomous Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified Autonomous VM cluster for an Exadata Cloud@Customer system. To get information about an Autonomous VM Cluster in the Oracle cloud, see [GetCloudAutonomousVmCluster](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudAutonomousVmCluster/GetCloudAutonomousVmCluster).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousVmCluster = oci.Database.getAutonomousVmCluster({
 *     autonomousVmClusterId: testAutonomousVmClusterOciDatabaseAutonomousVmCluster.id,
 * });
 * ```
 */
export function getAutonomousVmCluster(args: GetAutonomousVmClusterArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousVmClusterResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousVmCluster:getAutonomousVmCluster", {
        "autonomousVmClusterId": args.autonomousVmClusterId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousVmCluster.
 */
export interface GetAutonomousVmClusterArgs {
    /**
     * The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousVmClusterId: string;
}

/**
 * A collection of values returned by getAutonomousVmCluster.
 */
export interface GetAutonomousVmClusterResult {
    readonly autonomousDataStoragePercentage: number;
    /**
     * The data disk group size allocated for Autonomous Databases, in TBs.
     */
    readonly autonomousDataStorageSizeInTbs: number;
    readonly autonomousVmClusterId: string;
    /**
     * The data disk group size available for Autonomous Databases, in TBs.
     */
    readonly availableAutonomousDataStorageSizeInTbs: number;
    /**
     * The number of Autonomous Container Databases that can be created with the currently available local storage.
     */
    readonly availableContainerDatabases: number;
    /**
     * The numnber of CPU cores available.
     */
    readonly availableCpus: number;
    /**
     * **Deprecated.** Use `availableAutonomousDataStorageSizeInTBs` for Autonomous Databases' data storage availability in TBs.
     */
    readonly availableDataStorageSizeInTbs: number;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The compute model of the Autonomous VM Cluster. ECPU compute model is the recommended model and OCPU compute model is legacy. See [Compute Models in Autonomous Database on Dedicated Exadata #Infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/dedicated/adbak) for more details.
     */
    readonly computeModel: string;
    /**
     * The number of CPU cores enabled per VM cluster node.
     */
    readonly cpuCoreCountPerNode: number;
    readonly cpuPercentage: number;
    /**
     * The number of enabled CPU cores.
     */
    readonly cpusEnabled: number;
    /**
     * The lowest value to which cpus can be scaled down.
     */
    readonly cpusLowestScaledValue: number;
    /**
     * The total data storage allocated in GBs.
     */
    readonly dataStorageSizeInGb: number;
    /**
     * The total data storage allocated in TBs
     */
    readonly dataStorageSizeInTbs: number;
    /**
     * The local node storage allocated in GBs.
     */
    readonly dbNodeStorageSizeInGbs: number;
    /**
     * The list of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Db servers.
     */
    readonly dbServers: string[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
     */
    readonly displayName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    readonly exadataInfrastructureId: string;
    /**
     * The lowest value to which exadataStorage(in TBs) can be scaled down.
     */
    readonly exadataStorageInTbsLowestScaledValue: number;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous VM cluster.
     */
    readonly id: string;
    /**
     * If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
     */
    readonly isLocalBackupEnabled: boolean;
    /**
     * Enable mutual TLS(mTLS) authentication for database while provisioning a VMCluster. Default is TLS.
     */
    readonly isMtlsEnabled: boolean;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     */
    readonly lastMaintenanceRunId: string;
    /**
     * The Oracle license model that applies to the Autonomous VM cluster. The default is LICENSE_INCLUDED.
     */
    readonly licenseModel: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    readonly maintenanceWindowDetails: outputs.Database.GetAutonomousVmClusterMaintenanceWindowDetail[];
    /**
     * The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     */
    readonly maintenanceWindows: outputs.Database.GetAutonomousVmClusterMaintenanceWindow[];
    /**
     * The lowest value to which maximum number of ACDs can be scaled down.
     */
    readonly maxAcdsLowestScaledValue: number;
    /**
     * The amount of memory (in GBs) to be enabled per OCPU or ECPU.
     */
    readonly memoryPerOracleComputeUnitInGbs: number;
    /**
     * The memory allocated in GBs.
     */
    readonly memorySizeInGbs: number;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     */
    readonly nextMaintenanceRunId: string;
    /**
     * The number of nodes in the Autonomous VM Cluster.
     */
    readonly nodeCount: number;
    readonly nonProvisionableAutonomousContainerDatabases: number;
    /**
     * The number of enabled OCPU cores.
     */
    readonly ocpusEnabled: number;
    /**
     * **Deprecated.** Use field totalContainerDatabases.
     */
    readonly provisionableAutonomousContainerDatabases: number;
    /**
     * The number of provisioned Autonomous Container Databases in an Autonomous VM Cluster.
     */
    readonly provisionedAutonomousContainerDatabases: number;
    /**
     * The number of CPUs provisioned in an Autonomous VM Cluster.
     */
    readonly provisionedCpus: number;
    /**
     * For Autonomous Databases on Dedicated Exadata Infrastructure:
     * * These are the CPUs that continue to be included in the count of CPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available CPUs at its parent Autonomous VM Cluster level by restarting the Autonomous Container Database.
     * * The CPU type (OCPUs or ECPUs) is determined by the parent Autonomous Exadata VM Cluster's compute model.
     */
    readonly reclaimableCpus: number;
    /**
     * The number of CPUs reserved in an Autonomous VM Cluster.
     */
    readonly reservedCpus: number;
    /**
     * The SCAN Listener Non TLS port number. Default value is 1521.
     */
    readonly scanListenerPortNonTls: number;
    /**
     * The SCAN Listener TLS port number. Default value is 2484.
     */
    readonly scanListenerPortTls: number;
    /**
     * The current state of the Autonomous VM cluster.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time that the Autonomous VM cluster was created.
     */
    readonly timeCreated: string;
    /**
     * The date and time of Database SSL certificate expiration.
     */
    readonly timeDatabaseSslCertificateExpires: string;
    /**
     * The date and time of ORDS certificate expiration.
     */
    readonly timeOrdsCertificateExpires: string;
    /**
     * The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    readonly timeZone: string;
    readonly totalAutonomousDataStorageInTbs: number;
    /**
     * The total number of Autonomous Container Databases that can be created.
     */
    readonly totalContainerDatabases: number;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    readonly vmClusterNetworkId: string;
}
/**
 * This data source provides details about a specific Autonomous Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified Autonomous VM cluster for an Exadata Cloud@Customer system. To get information about an Autonomous VM Cluster in the Oracle cloud, see [GetCloudAutonomousVmCluster](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudAutonomousVmCluster/GetCloudAutonomousVmCluster).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousVmCluster = oci.Database.getAutonomousVmCluster({
 *     autonomousVmClusterId: testAutonomousVmClusterOciDatabaseAutonomousVmCluster.id,
 * });
 * ```
 */
export function getAutonomousVmClusterOutput(args: GetAutonomousVmClusterOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousVmClusterResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousVmCluster:getAutonomousVmCluster", {
        "autonomousVmClusterId": args.autonomousVmClusterId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousVmCluster.
 */
export interface GetAutonomousVmClusterOutputArgs {
    /**
     * The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousVmClusterId: pulumi.Input<string>;
}
