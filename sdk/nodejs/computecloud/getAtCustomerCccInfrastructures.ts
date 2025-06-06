// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Ccc Infrastructures in Oracle Cloud Infrastructure Compute Cloud At Customer service.
 *
 * Returns a list of Compute Cloud@Customer infrastructures.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCccInfrastructures = oci.ComputeCloud.getAtCustomerCccInfrastructures({
 *     accessLevel: cccInfrastructureAccessLevel,
 *     cccInfrastructureId: testCccInfrastructure.id,
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: cccInfrastructureCompartmentIdInSubtree,
 *     displayName: cccInfrastructureDisplayName,
 *     displayNameContains: cccInfrastructureDisplayNameContains,
 *     state: cccInfrastructureState,
 * });
 * ```
 */
export function getAtCustomerCccInfrastructures(args?: GetAtCustomerCccInfrastructuresArgs, opts?: pulumi.InvokeOptions): Promise<GetAtCustomerCccInfrastructuresResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ComputeCloud/getAtCustomerCccInfrastructures:getAtCustomerCccInfrastructures", {
        "accessLevel": args.accessLevel,
        "cccInfrastructureId": args.cccInfrastructureId,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "displayNameContains": args.displayNameContains,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAtCustomerCccInfrastructures.
 */
export interface GetAtCustomerCccInfrastructuresArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
     */
    cccInfrastructureId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    /**
     * A filter to return only resources whose display name contains the substring.
     */
    displayNameContains?: string;
    filters?: inputs.ComputeCloud.GetAtCustomerCccInfrastructuresFilter[];
    /**
     * A filter used to return only resources that match the given lifecycleState.
     */
    state?: string;
}

/**
 * A collection of values returned by getAtCustomerCccInfrastructures.
 */
export interface GetAtCustomerCccInfrastructuresResult {
    readonly accessLevel?: string;
    /**
     * The list of ccc_infrastructure_collection.
     */
    readonly cccInfrastructureCollections: outputs.ComputeCloud.GetAtCustomerCccInfrastructuresCccInfrastructureCollection[];
    readonly cccInfrastructureId?: string;
    /**
     * The infrastructure compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId?: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The name that will be used to display the Compute Cloud@Customer infrastructure in the Oracle Cloud Infrastructure console. Does not have to be unique and can be changed. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly displayNameContains?: string;
    readonly filters?: outputs.ComputeCloud.GetAtCustomerCccInfrastructuresFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Compute Cloud@Customer infrastructure.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Ccc Infrastructures in Oracle Cloud Infrastructure Compute Cloud At Customer service.
 *
 * Returns a list of Compute Cloud@Customer infrastructures.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCccInfrastructures = oci.ComputeCloud.getAtCustomerCccInfrastructures({
 *     accessLevel: cccInfrastructureAccessLevel,
 *     cccInfrastructureId: testCccInfrastructure.id,
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: cccInfrastructureCompartmentIdInSubtree,
 *     displayName: cccInfrastructureDisplayName,
 *     displayNameContains: cccInfrastructureDisplayNameContains,
 *     state: cccInfrastructureState,
 * });
 * ```
 */
export function getAtCustomerCccInfrastructuresOutput(args?: GetAtCustomerCccInfrastructuresOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAtCustomerCccInfrastructuresResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ComputeCloud/getAtCustomerCccInfrastructures:getAtCustomerCccInfrastructures", {
        "accessLevel": args.accessLevel,
        "cccInfrastructureId": args.cccInfrastructureId,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "displayNameContains": args.displayNameContains,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAtCustomerCccInfrastructures.
 */
export interface GetAtCustomerCccInfrastructuresOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
     */
    cccInfrastructureId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A filter to return only resources whose display name contains the substring.
     */
    displayNameContains?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ComputeCloud.GetAtCustomerCccInfrastructuresFilterArgs>[]>;
    /**
     * A filter used to return only resources that match the given lifecycleState.
     */
    state?: pulumi.Input<string>;
}
