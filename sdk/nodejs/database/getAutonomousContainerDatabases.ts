// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Autonomous Container Databases in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the Autonomous Container Databases in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousContainerDatabases = oci.Database.getAutonomousContainerDatabases({
 *     compartmentId: compartmentId,
 *     autonomousExadataInfrastructureId: testAutonomousExadataInfrastructure.id,
 *     autonomousVmClusterId: testAutonomousVmCluster.id,
 *     availabilityDomain: autonomousContainerDatabaseAvailabilityDomain,
 *     cloudAutonomousVmClusterId: testCloudAutonomousVmCluster.id,
 *     displayName: autonomousContainerDatabaseDisplayName,
 *     infrastructureType: autonomousContainerDatabaseInfrastructureType,
 *     serviceLevelAgreementType: autonomousContainerDatabaseServiceLevelAgreementType,
 *     state: autonomousContainerDatabaseState,
 * });
 * ```
 */
export function getAutonomousContainerDatabases(args: GetAutonomousContainerDatabasesArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousContainerDatabasesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousContainerDatabases:getAutonomousContainerDatabases", {
        "autonomousExadataInfrastructureId": args.autonomousExadataInfrastructureId,
        "autonomousVmClusterId": args.autonomousVmClusterId,
        "availabilityDomain": args.availabilityDomain,
        "cloudAutonomousVmClusterId": args.cloudAutonomousVmClusterId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "infrastructureType": args.infrastructureType,
        "serviceLevelAgreementType": args.serviceLevelAgreementType,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousContainerDatabases.
 */
export interface GetAutonomousContainerDatabasesArgs {
    /**
     * The Autonomous Exadata Infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousExadataInfrastructureId?: string;
    /**
     * The Autonomous VM Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousVmClusterId?: string;
    /**
     * A filter to return only resources that match the given availability domain exactly.
     */
    availabilityDomain?: string;
    /**
     * The cloud Autonomous VM Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    cloudAutonomousVmClusterId?: string;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.Database.GetAutonomousContainerDatabasesFilter[];
    /**
     * A filter to return only resources that match the given Infrastructure Type.
     */
    infrastructureType?: string;
    /**
     * A filter to return only resources that match the given service level agreement type exactly.
     */
    serviceLevelAgreementType?: string;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getAutonomousContainerDatabases.
 */
export interface GetAutonomousContainerDatabasesResult {
    /**
     * The list of autonomous_container_databases.
     */
    readonly autonomousContainerDatabases: outputs.Database.GetAutonomousContainerDatabasesAutonomousContainerDatabase[];
    /**
     * **No longer used.** For Autonomous Database on dedicated Exadata infrastructure, the container database is created within a specified `cloudAutonomousVmCluster`.
     */
    readonly autonomousExadataInfrastructureId?: string;
    /**
     * The OCID of the Autonomous VM Cluster.
     */
    readonly autonomousVmClusterId?: string;
    /**
     * The domain of the Autonomous Container Database
     */
    readonly availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
     */
    readonly cloudAutonomousVmClusterId?: string;
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-provided name for the Autonomous Container Database.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Database.GetAutonomousContainerDatabasesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The infrastructure type this resource belongs to.
     */
    readonly infrastructureType?: string;
    /**
     * The service level agreement type of the container database. The default is STANDARD.
     */
    readonly serviceLevelAgreementType?: string;
    /**
     * The current state of the Autonomous Container Database.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Autonomous Container Databases in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the Autonomous Container Databases in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousContainerDatabases = oci.Database.getAutonomousContainerDatabases({
 *     compartmentId: compartmentId,
 *     autonomousExadataInfrastructureId: testAutonomousExadataInfrastructure.id,
 *     autonomousVmClusterId: testAutonomousVmCluster.id,
 *     availabilityDomain: autonomousContainerDatabaseAvailabilityDomain,
 *     cloudAutonomousVmClusterId: testCloudAutonomousVmCluster.id,
 *     displayName: autonomousContainerDatabaseDisplayName,
 *     infrastructureType: autonomousContainerDatabaseInfrastructureType,
 *     serviceLevelAgreementType: autonomousContainerDatabaseServiceLevelAgreementType,
 *     state: autonomousContainerDatabaseState,
 * });
 * ```
 */
export function getAutonomousContainerDatabasesOutput(args: GetAutonomousContainerDatabasesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousContainerDatabasesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousContainerDatabases:getAutonomousContainerDatabases", {
        "autonomousExadataInfrastructureId": args.autonomousExadataInfrastructureId,
        "autonomousVmClusterId": args.autonomousVmClusterId,
        "availabilityDomain": args.availabilityDomain,
        "cloudAutonomousVmClusterId": args.cloudAutonomousVmClusterId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "infrastructureType": args.infrastructureType,
        "serviceLevelAgreementType": args.serviceLevelAgreementType,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousContainerDatabases.
 */
export interface GetAutonomousContainerDatabasesOutputArgs {
    /**
     * The Autonomous Exadata Infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The Autonomous VM Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousVmClusterId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given availability domain exactly.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The cloud Autonomous VM Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    cloudAutonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetAutonomousContainerDatabasesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given Infrastructure Type.
     */
    infrastructureType?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given service level agreement type exactly.
     */
    serviceLevelAgreementType?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
}
