// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Autonomous Databases Clones in Oracle Cloud Infrastructure Database service.
 *
 * Lists the Autonomous Database clones for the specified Autonomous Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabasesClones = oci.Database.getAutonomousDatabasesClones({
 *     autonomousDatabaseId: testAutonomousDatabase.id,
 *     compartmentId: compartmentId,
 *     cloneType: autonomousDatabasesCloneCloneType,
 *     displayName: autonomousDatabasesCloneDisplayName,
 *     state: autonomousDatabasesCloneState,
 * });
 * ```
 */
export function getAutonomousDatabasesClones(args: GetAutonomousDatabasesClonesArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousDatabasesClonesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", {
        "autonomousDatabaseId": args.autonomousDatabaseId,
        "cloneType": args.cloneType,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabasesClones.
 */
export interface GetAutonomousDatabasesClonesArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousDatabaseId: string;
    /**
     * A filter to return only resources that match the given clone type exactly.
     */
    cloneType?: string;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.Database.GetAutonomousDatabasesClonesFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getAutonomousDatabasesClones.
 */
export interface GetAutonomousDatabasesClonesResult {
    readonly autonomousDatabaseId: string;
    /**
     * The list of autonomous_databases.
     */
    readonly autonomousDatabases: outputs.Database.GetAutonomousDatabasesClonesAutonomousDatabase[];
    readonly cloneType?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the Autonomous Database. The name does not have to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Database.GetAutonomousDatabasesClonesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Autonomous Database.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Autonomous Databases Clones in Oracle Cloud Infrastructure Database service.
 *
 * Lists the Autonomous Database clones for the specified Autonomous Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabasesClones = oci.Database.getAutonomousDatabasesClones({
 *     autonomousDatabaseId: testAutonomousDatabase.id,
 *     compartmentId: compartmentId,
 *     cloneType: autonomousDatabasesCloneCloneType,
 *     displayName: autonomousDatabasesCloneDisplayName,
 *     state: autonomousDatabasesCloneState,
 * });
 * ```
 */
export function getAutonomousDatabasesClonesOutput(args: GetAutonomousDatabasesClonesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousDatabasesClonesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", {
        "autonomousDatabaseId": args.autonomousDatabaseId,
        "cloneType": args.cloneType,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabasesClones.
 */
export interface GetAutonomousDatabasesClonesOutputArgs {
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousDatabaseId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given clone type exactly.
     */
    cloneType?: pulumi.Input<string>;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetAutonomousDatabasesClonesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
}
