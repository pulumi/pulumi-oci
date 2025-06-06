// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific External Exadata Storage Connector resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the Exadata storage server connector specified by exadataStorageConnectorId.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalExadataStorageConnector = oci.DatabaseManagement.getExternalExadataStorageConnector({
 *     externalExadataStorageConnectorId: testExternalExadataStorageConnectorOciDatabaseManagementExternalExadataStorageConnector.id,
 * });
 * ```
 */
export function getExternalExadataStorageConnector(args: GetExternalExadataStorageConnectorArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalExadataStorageConnectorResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalExadataStorageConnector:getExternalExadataStorageConnector", {
        "externalExadataStorageConnectorId": args.externalExadataStorageConnectorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalExadataStorageConnector.
 */
export interface GetExternalExadataStorageConnectorArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connector to the Exadata storage server.
     */
    externalExadataStorageConnectorId: string;
}

/**
 * A collection of values returned by getExternalExadataStorageConnector.
 */
export interface GetExternalExadataStorageConnectorResult {
    /**
     * The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
     */
    readonly additionalDetails: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent for the Exadata storage server.
     */
    readonly agentId: string;
    /**
     * The unique string of the connection. For example, "https://<storage-server-name>/MS/RESTService/".
     */
    readonly connectionUri: string;
    readonly connectorName: string;
    readonly credentialInfos: outputs.DatabaseManagement.GetExternalExadataStorageConnectorCredentialInfo[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
     */
    readonly displayName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    readonly exadataInfrastructureId: string;
    readonly externalExadataStorageConnectorId: string;
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
     * The details of the lifecycle state of the Exadata resource.
     */
    readonly lifecycleDetails: string;
    /**
     * The current lifecycle state of the database resource.
     */
    readonly state: string;
    /**
     * The status of the Exadata resource.
     */
    readonly status: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata storage server.
     */
    readonly storageServerId: string;
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
 * This data source provides details about a specific External Exadata Storage Connector resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the Exadata storage server connector specified by exadataStorageConnectorId.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalExadataStorageConnector = oci.DatabaseManagement.getExternalExadataStorageConnector({
 *     externalExadataStorageConnectorId: testExternalExadataStorageConnectorOciDatabaseManagementExternalExadataStorageConnector.id,
 * });
 * ```
 */
export function getExternalExadataStorageConnectorOutput(args: GetExternalExadataStorageConnectorOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetExternalExadataStorageConnectorResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getExternalExadataStorageConnector:getExternalExadataStorageConnector", {
        "externalExadataStorageConnectorId": args.externalExadataStorageConnectorId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalExadataStorageConnector.
 */
export interface GetExternalExadataStorageConnectorOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connector to the Exadata storage server.
     */
    externalExadataStorageConnectorId: pulumi.Input<string>;
}
