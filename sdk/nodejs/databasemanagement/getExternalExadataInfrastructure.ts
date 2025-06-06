// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific External Exadata Infrastructure resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the Exadata infrastructure specified by externalExadataInfrastructureId. It includes the DB systems and storage grid within the
 * Exadata infrastructure.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalExadataInfrastructure = oci.DatabaseManagement.getExternalExadataInfrastructure({
 *     externalExadataInfrastructureId: testExternalExadataInfrastructureOciDatabaseManagementExternalExadataInfrastructure.id,
 * });
 * ```
 */
export function getExternalExadataInfrastructure(args: GetExternalExadataInfrastructureArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalExadataInfrastructureResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalExadataInfrastructure:getExternalExadataInfrastructure", {
        "externalExadataInfrastructureId": args.externalExadataInfrastructureId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalExadataInfrastructure.
 */
export interface GetExternalExadataInfrastructureArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    externalExadataInfrastructureId: string;
}

/**
 * A collection of values returned by getExternalExadataInfrastructure.
 */
export interface GetExternalExadataInfrastructureResult {
    /**
     * The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
     */
    readonly additionalDetails: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
     */
    readonly databaseCompartments: string[];
    /**
     * A list of DB systems.
     */
    readonly databaseSystems: outputs.DatabaseManagement.GetExternalExadataInfrastructureDatabaseSystem[];
    readonly dbSystemIds: string[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    readonly discoveryKey: string;
    /**
     * The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
     */
    readonly displayName: string;
    readonly externalExadataInfrastructureId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
     */
    readonly id: string;
    /**
     * The internal ID of the Exadata resource.
     */
    readonly internalId: string;
    /**
     * The Oracle license model that applies to the database management resources.
     */
    readonly licenseModel: string;
    /**
     * The details of the lifecycle state of the Exadata resource.
     */
    readonly lifecycleDetails: string;
    /**
     * The rack size of the Exadata infrastructure.
     */
    readonly rackSize: string;
    /**
     * The current lifecycle state of the database resource.
     */
    readonly state: string;
    /**
     * The status of the Exadata resource.
     */
    readonly status: string;
    /**
     * The Exadata storage server grid of the Exadata infrastructure.
     */
    readonly storageGrids: outputs.DatabaseManagement.GetExternalExadataInfrastructureStorageGrid[];
    readonly storageServerNames: string[];
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The timestamp of the creation of the Exadata resource.
     */
    readonly timeCreated: string;
    /**
     * The timestamp of the last update of the Exadata resource.
     */
    readonly timeUpdated: string;
    /**
     * The version of the Exadata resource.
     */
    readonly version: string;
}
/**
 * This data source provides details about a specific External Exadata Infrastructure resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the Exadata infrastructure specified by externalExadataInfrastructureId. It includes the DB systems and storage grid within the
 * Exadata infrastructure.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalExadataInfrastructure = oci.DatabaseManagement.getExternalExadataInfrastructure({
 *     externalExadataInfrastructureId: testExternalExadataInfrastructureOciDatabaseManagementExternalExadataInfrastructure.id,
 * });
 * ```
 */
export function getExternalExadataInfrastructureOutput(args: GetExternalExadataInfrastructureOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetExternalExadataInfrastructureResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getExternalExadataInfrastructure:getExternalExadataInfrastructure", {
        "externalExadataInfrastructureId": args.externalExadataInfrastructureId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalExadataInfrastructure.
 */
export interface GetExternalExadataInfrastructureOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    externalExadataInfrastructureId: pulumi.Input<string>;
}
