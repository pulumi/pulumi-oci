// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Retrieves a deployment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployment = oci.GoldenGate.getDeployment({
 *     deploymentId: oci_golden_gate_deployment.test_deployment.id,
 * });
 * ```
 */
export function getDeployment(args: GetDeploymentArgs, opts?: pulumi.InvokeOptions): Promise<GetDeploymentResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:GoldenGate/getDeployment:getDeployment", {
        "deploymentId": args.deploymentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDeployment.
 */
export interface GetDeploymentArgs {
    /**
     * A unique Deployment identifier.
     */
    deploymentId: string;
}

/**
 * A collection of values returned by getDeployment.
 */
export interface GetDeploymentResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     */
    readonly compartmentId: string;
    /**
     * The Minimum number of OCPUs to be made available for this Deployment.
     */
    readonly cpuCoreCount: number;
    /**
     * Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
     */
    readonly deploymentBackupId: string;
    readonly deploymentId: string;
    /**
     * The deployment type.
     */
    readonly deploymentType: string;
    /**
     * The URL of a resource.
     */
    readonly deploymentUrl: string;
    /**
     * Metadata about this specific object.
     */
    readonly description: string;
    /**
     * An object's Display Name.
     */
    readonly displayName: string;
    /**
     * A three-label Fully Qualified Domain Name (FQDN) for a resource.
     */
    readonly fqdn: string;
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
     */
    readonly id: string;
    /**
     * Indicates if auto scaling is enabled for the Deployment's CPU core count.
     */
    readonly isAutoScalingEnabled: boolean;
    /**
     * True if all of the aggregate resources are working correctly.
     */
    readonly isHealthy: boolean;
    /**
     * Indicates if the resource is the the latest available version.
     */
    readonly isLatestVersion: boolean;
    /**
     * True if this object is publicly available.
     */
    readonly isPublic: boolean;
    /**
     * Indicator will be true if the amount of storage being utilized exceeds the allowable storage utilization limit.  Exceeding the limit may be an indication of a misconfiguration of the deployment's GoldenGate service.
     */
    readonly isStorageUtilizationLimitExceeded: boolean;
    /**
     * The Oracle license model that applies to a Deployment.
     */
    readonly licenseModel: string;
    /**
     * Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Possible GGS lifecycle sub-states.
     */
    readonly lifecycleSubState: string;
    /**
     * An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
     */
    readonly nsgIds: string[];
    /**
     * Deployment Data for an OggDeployment
     */
    readonly oggDatas: outputs.GoldenGate.GetDeploymentOggData[];
    /**
     * The private IP address in the customer's VCN representing the access point for the associated endpoint service in the GoldenGate service VCN.
     */
    readonly privateIpAddress: string;
    /**
     * The public IP address representing the access point for the Deployment.
     */
    readonly publicIpAddress: string;
    /**
     * Possible lifecycle states.
     */
    readonly state: string;
    /**
     * The amount of storage being utilized (in bytes)
     */
    readonly storageUtilizationInBytes: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
     */
    readonly subnetId: string;
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeCreated: string;
    /**
     * The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeUpdated: string;
    /**
     * The date the existing version in use will no longer be considered as usable and an upgrade will be required.  This date is typically 6 months after the version was released for use by GGS.  The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeUpgradeRequired: string;
}

export function getDeploymentOutput(args: GetDeploymentOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDeploymentResult> {
    return pulumi.output(args).apply(a => getDeployment(a, opts))
}

/**
 * A collection of arguments for invoking getDeployment.
 */
export interface GetDeploymentOutputArgs {
    /**
     * A unique Deployment identifier.
     */
    deploymentId: pulumi.Input<string>;
}