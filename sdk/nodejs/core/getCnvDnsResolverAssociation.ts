// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vcn Dns Resolver Association resource in Oracle Cloud Infrastructure Core service.
 *
 * Get the associated DNS resolver information with a vcn
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVcnDnsResolverAssociation = oci.Core.getCnvDnsResolverAssociation({
 *     vcnId: oci_core_vcn.test_vcn.id,
 * });
 * ```
 */
export function getCnvDnsResolverAssociation(args: GetCnvDnsResolverAssociationArgs, opts?: pulumi.InvokeOptions): Promise<GetCnvDnsResolverAssociationResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getCnvDnsResolverAssociation:getCnvDnsResolverAssociation", {
        "vcnId": args.vcnId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCnvDnsResolverAssociation.
 */
export interface GetCnvDnsResolverAssociationArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    vcnId: string;
}

/**
 * A collection of values returned by getCnvDnsResolverAssociation.
 */
export interface GetCnvDnsResolverAssociationResult {
    /**
     * The OCID of the DNS resolver in the association. We won't have the DNS resolver id as soon as vcn 
     * is created, we will create it asynchronously. It would be null until it is actually created.
     */
    readonly dnsResolverId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly state: string;
    /**
     * The OCID of the VCN in the association.
     */
    readonly vcnId: string;
}

export function getCnvDnsResolverAssociationOutput(args: GetCnvDnsResolverAssociationOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetCnvDnsResolverAssociationResult> {
    return pulumi.output(args).apply(a => getCnvDnsResolverAssociation(a, opts))
}

/**
 * A collection of arguments for invoking getCnvDnsResolverAssociation.
 */
export interface GetCnvDnsResolverAssociationOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    vcnId: pulumi.Input<string>;
}