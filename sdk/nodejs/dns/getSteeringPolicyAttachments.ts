// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Steering Policy Attachments in Oracle Cloud Infrastructure DNS service.
 *
 * Lists the steering policy attachments in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSteeringPolicyAttachments = oci.Dns.getSteeringPolicyAttachments({
 *     compartmentId: compartmentId,
 *     displayName: steeringPolicyAttachmentDisplayName,
 *     domain: steeringPolicyAttachmentDomain,
 *     domainContains: steeringPolicyAttachmentDomainContains,
 *     id: steeringPolicyAttachmentId,
 *     state: steeringPolicyAttachmentState,
 *     steeringPolicyId: testSteeringPolicy.id,
 *     timeCreatedGreaterThanOrEqualTo: steeringPolicyAttachmentTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: steeringPolicyAttachmentTimeCreatedLessThan,
 *     zoneId: testZone.id,
 * });
 * ```
 */
export function getSteeringPolicyAttachments(args: GetSteeringPolicyAttachmentsArgs, opts?: pulumi.InvokeOptions): Promise<GetSteeringPolicyAttachmentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Dns/getSteeringPolicyAttachments:getSteeringPolicyAttachments", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "domain": args.domain,
        "domainContains": args.domainContains,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
        "steeringPolicyId": args.steeringPolicyId,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "zoneId": args.zoneId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSteeringPolicyAttachments.
 */
export interface GetSteeringPolicyAttachmentsArgs {
    /**
     * The OCID of the compartment the resource belongs to.
     */
    compartmentId: string;
    /**
     * The displayName of a resource.
     */
    displayName?: string;
    /**
     * Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
     */
    domain?: string;
    /**
     * Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
     */
    domainContains?: string;
    filters?: inputs.Dns.GetSteeringPolicyAttachmentsFilter[];
    /**
     * The OCID of a resource.
     */
    id?: string;
    /**
     * The state of a resource.
     */
    state?: string;
    /**
     * Search by steering policy OCID. Will match any resource whose steering policy ID matches the provided value.
     */
    steeringPolicyId?: string;
    /**
     * An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created on or after the indicated time.
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created before the indicated time.
     */
    timeCreatedLessThan?: string;
    /**
     * Search by zone OCID. Will match any resource whose zone ID matches the provided value.
     */
    zoneId?: string;
}

/**
 * A collection of values returned by getSteeringPolicyAttachments.
 */
export interface GetSteeringPolicyAttachmentsResult {
    /**
     * The OCID of the compartment containing the steering policy attachment.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name for the steering policy attachment. Does not have to be unique and can be changed. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly domain?: string;
    readonly domainContains?: string;
    readonly filters?: outputs.Dns.GetSteeringPolicyAttachmentsFilter[];
    /**
     * The OCID of the resource.
     */
    readonly id?: string;
    /**
     * The current state of the resource.
     */
    readonly state?: string;
    /**
     * The list of steering_policy_attachments.
     */
    readonly steeringPolicyAttachments: outputs.Dns.GetSteeringPolicyAttachmentsSteeringPolicyAttachment[];
    /**
     * The OCID of the attached steering policy.
     */
    readonly steeringPolicyId?: string;
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
    /**
     * The OCID of the attached zone.
     */
    readonly zoneId?: string;
}
/**
 * This data source provides the list of Steering Policy Attachments in Oracle Cloud Infrastructure DNS service.
 *
 * Lists the steering policy attachments in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSteeringPolicyAttachments = oci.Dns.getSteeringPolicyAttachments({
 *     compartmentId: compartmentId,
 *     displayName: steeringPolicyAttachmentDisplayName,
 *     domain: steeringPolicyAttachmentDomain,
 *     domainContains: steeringPolicyAttachmentDomainContains,
 *     id: steeringPolicyAttachmentId,
 *     state: steeringPolicyAttachmentState,
 *     steeringPolicyId: testSteeringPolicy.id,
 *     timeCreatedGreaterThanOrEqualTo: steeringPolicyAttachmentTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: steeringPolicyAttachmentTimeCreatedLessThan,
 *     zoneId: testZone.id,
 * });
 * ```
 */
export function getSteeringPolicyAttachmentsOutput(args: GetSteeringPolicyAttachmentsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSteeringPolicyAttachmentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Dns/getSteeringPolicyAttachments:getSteeringPolicyAttachments", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "domain": args.domain,
        "domainContains": args.domainContains,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
        "steeringPolicyId": args.steeringPolicyId,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "zoneId": args.zoneId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSteeringPolicyAttachments.
 */
export interface GetSteeringPolicyAttachmentsOutputArgs {
    /**
     * The OCID of the compartment the resource belongs to.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The displayName of a resource.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
     */
    domain?: pulumi.Input<string>;
    /**
     * Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
     */
    domainContains?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Dns.GetSteeringPolicyAttachmentsFilterArgs>[]>;
    /**
     * The OCID of a resource.
     */
    id?: pulumi.Input<string>;
    /**
     * The state of a resource.
     */
    state?: pulumi.Input<string>;
    /**
     * Search by steering policy OCID. Will match any resource whose steering policy ID matches the provided value.
     */
    steeringPolicyId?: pulumi.Input<string>;
    /**
     * An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created on or after the indicated time.
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created before the indicated time.
     */
    timeCreatedLessThan?: pulumi.Input<string>;
    /**
     * Search by zone OCID. Will match any resource whose zone ID matches the provided value.
     */
    zoneId?: pulumi.Input<string>;
}
