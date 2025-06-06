// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Ccc Infrastructure resource in Oracle Cloud Infrastructure Compute Cloud At Customer service.
 *
 * Gets a Compute Cloud@Customer infrastructure using the infrastructure
 * [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCccInfrastructure = oci.ComputeCloud.getAtCustomerCccInfrastructure({
 *     cccInfrastructureId: testCccInfrastructureOciComputeCloudAtCustomerCccInfrastructure.id,
 * });
 * ```
 */
export function getAtCustomerCccInfrastructure(args: GetAtCustomerCccInfrastructureArgs, opts?: pulumi.InvokeOptions): Promise<GetAtCustomerCccInfrastructureResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ComputeCloud/getAtCustomerCccInfrastructure:getAtCustomerCccInfrastructure", {
        "cccInfrastructureId": args.cccInfrastructureId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAtCustomerCccInfrastructure.
 */
export interface GetAtCustomerCccInfrastructureArgs {
    /**
     * An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
     */
    cccInfrastructureId: string;
}

/**
 * A collection of values returned by getAtCustomerCccInfrastructure.
 */
export interface GetAtCustomerCccInfrastructureResult {
    readonly cccInfrastructureId: string;
    /**
     * Schedule used for upgrades. If no schedule is associated with the infrastructure, it can be updated at any time.
     */
    readonly cccUpgradeScheduleId: string;
    /**
     * The infrastructure compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    /**
     * A message describing the current connection state in more detail.
     */
    readonly connectionDetails: string;
    /**
     * The current connection state of the infrastructure. A user can only update it from REQUEST to READY or from any state back to REJECT. The system automatically handles the REJECT to REQUEST, READY to CONNECTED, or CONNECTED to DISCONNECTED transitions.
     */
    readonly connectionState: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A mutable client-meaningful text description of the Compute Cloud@Customer infrastructure. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * The name that will be used to display the Compute Cloud@Customer infrastructure in the Oracle Cloud Infrastructure console. Does not have to be unique and can be changed. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The Compute Cloud@Customer infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This cannot be changed once created.
     */
    readonly id: string;
    /**
     * Inventory for a Compute Cloud@Customer infrastructure. This information cannot be updated and is from the infrastructure. The information will only be available after the connectionState is transitioned to CONNECTED.
     */
    readonly infrastructureInventories: outputs.ComputeCloud.GetAtCustomerCccInfrastructureInfrastructureInventory[];
    /**
     * Configuration information for the Compute Cloud@Customer infrastructure. This  network configuration information cannot be updated and is retrieved from the data center. The information will only be available after the connectionState is transitioned to CONNECTED.
     */
    readonly infrastructureNetworkConfigurations: outputs.ComputeCloud.GetAtCustomerCccInfrastructureInfrastructureNetworkConfiguration[];
    /**
     * A message describing the current lifecycle state in more detail. For example, this can be used to provide actionable information for a resource that is in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Fingerprint of a Compute Cloud@Customer infrastructure in a data center generated during the initial connection to this resource. The fingerprint should be verified by the administrator when changing the connectionState from REQUEST to READY.
     */
    readonly provisioningFingerprint: string;
    /**
     * Code that is required for service personnel to connect a Compute Cloud@Customer infrastructure in a data center to this resource. This code will only be available when the connectionState is REJECT (usually at create time of the Compute Cloud@Customer infrastructure).
     */
    readonly provisioningPin: string;
    /**
     * The Compute Cloud@Customer infrastructure short name. This cannot be changed once created. The short name is used to refer to the infrastructure in several contexts and is unique.
     */
    readonly shortName: string;
    /**
     * The current state of the Compute Cloud@Customer infrastructure.
     */
    readonly state: string;
    /**
     * [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the network subnet that is used to communicate with Compute Cloud@Customer infrastructure.
     */
    readonly subnetId: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * Compute Cloud@Customer infrastructure creation date and time, using an RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * Compute Cloud@Customer infrastructure updated date and time, using an RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    /**
     * Upgrade information that relates to a Compute Cloud@Customer infrastructure. This information cannot be updated.
     */
    readonly upgradeInformations: outputs.ComputeCloud.GetAtCustomerCccInfrastructureUpgradeInformation[];
}
/**
 * This data source provides details about a specific Ccc Infrastructure resource in Oracle Cloud Infrastructure Compute Cloud At Customer service.
 *
 * Gets a Compute Cloud@Customer infrastructure using the infrastructure
 * [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCccInfrastructure = oci.ComputeCloud.getAtCustomerCccInfrastructure({
 *     cccInfrastructureId: testCccInfrastructureOciComputeCloudAtCustomerCccInfrastructure.id,
 * });
 * ```
 */
export function getAtCustomerCccInfrastructureOutput(args: GetAtCustomerCccInfrastructureOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAtCustomerCccInfrastructureResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ComputeCloud/getAtCustomerCccInfrastructure:getAtCustomerCccInfrastructure", {
        "cccInfrastructureId": args.cccInfrastructureId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAtCustomerCccInfrastructure.
 */
export interface GetAtCustomerCccInfrastructureOutputArgs {
    /**
     * An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
     */
    cccInfrastructureId: pulumi.Input<string>;
}
