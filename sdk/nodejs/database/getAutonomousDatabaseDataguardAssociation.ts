// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Autonomous Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets an Autonomous Database dataguard assocation for the specified Autonomous Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseDataguardAssociation = oci.Database.getAutonomousDatabaseDataguardAssociation({
 *     autonomousDatabaseDataguardAssociationId: testAutonomousDatabaseDataguardAssociationOciDatabaseAutonomousDatabaseDataguardAssociation.id,
 *     autonomousDatabaseId: testAutonomousDatabase.id,
 * });
 * ```
 */
export function getAutonomousDatabaseDataguardAssociation(args: GetAutonomousDatabaseDataguardAssociationArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousDatabaseDataguardAssociationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousDatabaseDataguardAssociation:getAutonomousDatabaseDataguardAssociation", {
        "autonomousDatabaseDataguardAssociationId": args.autonomousDatabaseDataguardAssociationId,
        "autonomousDatabaseId": args.autonomousDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabaseDataguardAssociation.
 */
export interface GetAutonomousDatabaseDataguardAssociationArgs {
    /**
     * The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousDatabaseDataguardAssociationId: string;
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousDatabaseId: string;
}

/**
 * A collection of values returned by getAutonomousDatabaseDataguardAssociation.
 */
export interface GetAutonomousDatabaseDataguardAssociationResult {
    /**
     * The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
     */
    readonly applyLag: string;
    /**
     * The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
     */
    readonly applyRate: string;
    readonly autonomousDatabaseDataguardAssociationId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database that has a relationship with the peer Autonomous Database.
     */
    readonly autonomousDatabaseId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Additional information about the current lifecycleState, if available.
     */
    readonly lifecycleDetails: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Database.
     */
    readonly peerAutonomousDatabaseId: string;
    /**
     * The current state of the Autonomous Dataguard.
     */
    readonly peerAutonomousDatabaseLifeCycleState: string;
    /**
     * The role of the Autonomous Dataguard enabled Autonomous Container Database.
     */
    readonly peerRole: string;
    /**
     * The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     */
    readonly protectionMode: string;
    /**
     * The role of the Autonomous Dataguard enabled Autonomous Container Database.
     */
    readonly role: string;
    /**
     * The current state of the Autonomous Dataguard.
     */
    readonly state: string;
    /**
     * The date and time the Data Guard association was created.
     */
    readonly timeCreated: string;
    /**
     * The date and time when the last role change action happened.
     */
    readonly timeLastRoleChanged: string;
}
/**
 * This data source provides details about a specific Autonomous Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets an Autonomous Database dataguard assocation for the specified Autonomous Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseDataguardAssociation = oci.Database.getAutonomousDatabaseDataguardAssociation({
 *     autonomousDatabaseDataguardAssociationId: testAutonomousDatabaseDataguardAssociationOciDatabaseAutonomousDatabaseDataguardAssociation.id,
 *     autonomousDatabaseId: testAutonomousDatabase.id,
 * });
 * ```
 */
export function getAutonomousDatabaseDataguardAssociationOutput(args: GetAutonomousDatabaseDataguardAssociationOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousDatabaseDataguardAssociationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousDatabaseDataguardAssociation:getAutonomousDatabaseDataguardAssociation", {
        "autonomousDatabaseDataguardAssociationId": args.autonomousDatabaseDataguardAssociationId,
        "autonomousDatabaseId": args.autonomousDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabaseDataguardAssociation.
 */
export interface GetAutonomousDatabaseDataguardAssociationOutputArgs {
    /**
     * The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousDatabaseDataguardAssociationId: pulumi.Input<string>;
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousDatabaseId: pulumi.Input<string>;
}
