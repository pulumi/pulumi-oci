// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Audit Trails in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of all audit trails.
 * The ListAuditTrails operation returns only the audit trails in the specified `compartmentId`.
 * The list does not include any subcompartments of the compartmentId passed.
 *
 * The parameter `accessLevel` specifies whether to return only those compartments for which the
 * requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListAuditTrails on the
 * `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
 * To get a full list of all compartments and subcompartments in the tenancy (root compartment),
 * set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAuditTrails = oci.DataSafe.getAuditTrails({
 *     compartmentId: _var.compartment_id,
 *     accessLevel: _var.audit_trail_access_level,
 *     auditTrailId: oci_data_safe_audit_trail.test_audit_trail.id,
 *     compartmentIdInSubtree: _var.audit_trail_compartment_id_in_subtree,
 *     displayName: _var.audit_trail_display_name,
 *     state: _var.audit_trail_state,
 *     status: _var.audit_trail_status,
 *     targetId: oci_cloud_guard_target.test_target.id,
 * });
 * ```
 */
export function getAuditTrails(args: GetAuditTrailsArgs, opts?: pulumi.InvokeOptions): Promise<GetAuditTrailsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataSafe/getAuditTrails:getAuditTrails", {
        "accessLevel": args.accessLevel,
        "auditTrailId": args.auditTrailId,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "status": args.status,
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAuditTrails.
 */
export interface GetAuditTrailsArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * A optional filter to return only resources that match the specified id.
     */
    auditTrailId?: string;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: string;
    filters?: inputs.DataSafe.GetAuditTrailsFilter[];
    /**
     * A optional filter to return only resources that match the specified lifecycle state.
     */
    state?: string;
    /**
     * A optional filter to return only resources that match the specified sub-state of audit trail.
     */
    status?: string;
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: string;
}

/**
 * A collection of values returned by getAuditTrails.
 */
export interface GetAuditTrailsResult {
    readonly accessLevel?: string;
    /**
     * The list of audit_trail_collection.
     */
    readonly auditTrailCollections: outputs.DataSafe.GetAuditTrailsAuditTrailCollection[];
    readonly auditTrailId?: string;
    /**
     * The OCID of the compartment that contains the audit trail and its same as the compartment of audit profile resource.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The display name of the audit trail.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DataSafe.GetAuditTrailsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the audit trail.
     */
    readonly state?: string;
    /**
     * The current sub-state of the audit trail.
     */
    readonly status?: string;
    /**
     * The OCID of the Data Safe target for which the audit trail is created.
     */
    readonly targetId?: string;
}

export function getAuditTrailsOutput(args: GetAuditTrailsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAuditTrailsResult> {
    return pulumi.output(args).apply(a => getAuditTrails(a, opts))
}

/**
 * A collection of arguments for invoking getAuditTrails.
 */
export interface GetAuditTrailsOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * A optional filter to return only resources that match the specified id.
     */
    auditTrailId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetAuditTrailsFilterArgs>[]>;
    /**
     * A optional filter to return only resources that match the specified lifecycle state.
     */
    state?: pulumi.Input<string>;
    /**
     * A optional filter to return only resources that match the specified sub-state of audit trail.
     */
    status?: pulumi.Input<string>;
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: pulumi.Input<string>;
}