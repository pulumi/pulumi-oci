// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sender Invitations in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Return a (paginated) list of sender invitations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSenderInvitations = oci.Tenantmanagercontrolplane.getSenderInvitations({
 *     compartmentId: compartmentId,
 *     displayName: senderInvitationDisplayName,
 *     recipientTenancyId: testTenancy.id,
 *     state: senderInvitationState,
 *     status: senderInvitationStatus,
 * });
 * ```
 */
export function getSenderInvitations(args: GetSenderInvitationsArgs, opts?: pulumi.InvokeOptions): Promise<GetSenderInvitationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Tenantmanagercontrolplane/getSenderInvitations:getSenderInvitations", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "recipientTenancyId": args.recipientTenancyId,
        "state": args.state,
        "status": args.status,
    }, opts);
}

/**
 * A collection of arguments for invoking getSenderInvitations.
 */
export interface GetSenderInvitationsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.Tenantmanagercontrolplane.GetSenderInvitationsFilter[];
    /**
     * The tenancy that the invitation is addressed to.
     */
    recipientTenancyId?: string;
    /**
     * The lifecycle state of the resource.
     */
    state?: string;
    /**
     * The status of the sender invitation.
     */
    status?: string;
}

/**
 * A collection of values returned by getSenderInvitations.
 */
export interface GetSenderInvitationsResult {
    /**
     * OCID of the sender tenancy.
     */
    readonly compartmentId: string;
    /**
     * A user-created name to describe the invitation. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Tenantmanagercontrolplane.GetSenderInvitationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * OCID of the recipient tenancy.
     */
    readonly recipientTenancyId?: string;
    /**
     * The list of sender_invitation_collection.
     */
    readonly senderInvitationCollections: outputs.Tenantmanagercontrolplane.GetSenderInvitationsSenderInvitationCollection[];
    /**
     * Lifecycle state of the sender invitation.
     */
    readonly state?: string;
    /**
     * Status of the sender invitation.
     */
    readonly status?: string;
}
/**
 * This data source provides the list of Sender Invitations in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
 *
 * Return a (paginated) list of sender invitations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSenderInvitations = oci.Tenantmanagercontrolplane.getSenderInvitations({
 *     compartmentId: compartmentId,
 *     displayName: senderInvitationDisplayName,
 *     recipientTenancyId: testTenancy.id,
 *     state: senderInvitationState,
 *     status: senderInvitationStatus,
 * });
 * ```
 */
export function getSenderInvitationsOutput(args: GetSenderInvitationsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSenderInvitationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Tenantmanagercontrolplane/getSenderInvitations:getSenderInvitations", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "recipientTenancyId": args.recipientTenancyId,
        "state": args.state,
        "status": args.status,
    }, opts);
}

/**
 * A collection of arguments for invoking getSenderInvitations.
 */
export interface GetSenderInvitationsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Tenantmanagercontrolplane.GetSenderInvitationsFilterArgs>[]>;
    /**
     * The tenancy that the invitation is addressed to.
     */
    recipientTenancyId?: pulumi.Input<string>;
    /**
     * The lifecycle state of the resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The status of the sender invitation.
     */
    status?: pulumi.Input<string>;
}
