// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Recovery Service Subnets in Oracle Cloud Infrastructure Recovery service.
 *
 * Returns a list of Recovery Service Subnets.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRecoveryServiceSubnets = oci.RecoveryMod.getRecoveryServiceSubnets({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.recovery_service_subnet_display_name,
 *     id: _var.recovery_service_subnet_id,
 *     state: _var.recovery_service_subnet_state,
 *     vcnId: oci_core_vcn.test_vcn.id,
 * });
 * ```
 */
export function getRecoveryServiceSubnets(args: GetRecoveryServiceSubnetsArgs, opts?: pulumi.InvokeOptions): Promise<GetRecoveryServiceSubnetsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:RecoveryMod/getRecoveryServiceSubnets:getRecoveryServiceSubnets", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
        "vcnId": args.vcnId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRecoveryServiceSubnets.
 */
export interface GetRecoveryServiceSubnetsArgs {
    /**
     * The compartment OCID.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire 'displayname' given.
     */
    displayName?: string;
    filters?: inputs.RecoveryMod.GetRecoveryServiceSubnetsFilter[];
    /**
     * The recovery service subnet OCID.
     */
    id?: string;
    /**
     * A filter to return only the resources that match the specified lifecycle state. Allowed values are:
     * * CREATING
     * * UPDATING
     * * ACTIVE
     * * DELETING
     * * DELETED
     * * FAILED
     */
    state?: string;
    /**
     * The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
     */
    vcnId?: string;
}

/**
 * A collection of values returned by getRecoveryServiceSubnets.
 */
export interface GetRecoveryServiceSubnetsResult {
    /**
     * The compartment OCID.
     */
    readonly compartmentId: string;
    /**
     * A user-provided name for the recovery service subnet.
     */
    readonly displayName?: string;
    readonly filters?: outputs.RecoveryMod.GetRecoveryServiceSubnetsFilter[];
    /**
     * The recovery service subnet OCID.
     */
    readonly id?: string;
    /**
     * The list of recovery_service_subnet_collection.
     */
    readonly recoveryServiceSubnetCollections: outputs.RecoveryMod.GetRecoveryServiceSubnetsRecoveryServiceSubnetCollection[];
    /**
     * The current state of the recovery service subnet. Allowed values are:
     * * CREATING
     * * UPDATING
     * * ACTIVE
     * * DELETING
     * * DELETED
     * * FAILED
     */
    readonly state?: string;
    /**
     * VCN Identifier.
     */
    readonly vcnId?: string;
}
/**
 * This data source provides the list of Recovery Service Subnets in Oracle Cloud Infrastructure Recovery service.
 *
 * Returns a list of Recovery Service Subnets.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRecoveryServiceSubnets = oci.RecoveryMod.getRecoveryServiceSubnets({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.recovery_service_subnet_display_name,
 *     id: _var.recovery_service_subnet_id,
 *     state: _var.recovery_service_subnet_state,
 *     vcnId: oci_core_vcn.test_vcn.id,
 * });
 * ```
 */
export function getRecoveryServiceSubnetsOutput(args: GetRecoveryServiceSubnetsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetRecoveryServiceSubnetsResult> {
    return pulumi.output(args).apply((a: any) => getRecoveryServiceSubnets(a, opts))
}

/**
 * A collection of arguments for invoking getRecoveryServiceSubnets.
 */
export interface GetRecoveryServiceSubnetsOutputArgs {
    /**
     * The compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire 'displayname' given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.RecoveryMod.GetRecoveryServiceSubnetsFilterArgs>[]>;
    /**
     * The recovery service subnet OCID.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that match the specified lifecycle state. Allowed values are:
     * * CREATING
     * * UPDATING
     * * ACTIVE
     * * DELETING
     * * DELETED
     * * FAILED
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
     */
    vcnId?: pulumi.Input<string>;
}