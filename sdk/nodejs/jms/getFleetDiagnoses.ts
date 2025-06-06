// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Fleet Diagnoses in Oracle Cloud Infrastructure Jms service.
 *
 * List potential diagnoses that would put a fleet into FAILED or NEEDS_ATTENTION lifecycle state.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetDiagnoses = oci.Jms.getFleetDiagnoses({
 *     fleetId: testFleet.id,
 * });
 * ```
 */
export function getFleetDiagnoses(args: GetFleetDiagnosesArgs, opts?: pulumi.InvokeOptions): Promise<GetFleetDiagnosesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getFleetDiagnoses:getFleetDiagnoses", {
        "filters": args.filters,
        "fleetId": args.fleetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetDiagnoses.
 */
export interface GetFleetDiagnosesArgs {
    filters?: inputs.Jms.GetFleetDiagnosesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: string;
}

/**
 * A collection of values returned by getFleetDiagnoses.
 */
export interface GetFleetDiagnosesResult {
    readonly filters?: outputs.Jms.GetFleetDiagnosesFilter[];
    /**
     * The list of fleet_diagnosis_collection.
     */
    readonly fleetDiagnosisCollections: outputs.Jms.GetFleetDiagnosesFleetDiagnosisCollection[];
    readonly fleetId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Fleet Diagnoses in Oracle Cloud Infrastructure Jms service.
 *
 * List potential diagnoses that would put a fleet into FAILED or NEEDS_ATTENTION lifecycle state.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetDiagnoses = oci.Jms.getFleetDiagnoses({
 *     fleetId: testFleet.id,
 * });
 * ```
 */
export function getFleetDiagnosesOutput(args: GetFleetDiagnosesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetFleetDiagnosesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Jms/getFleetDiagnoses:getFleetDiagnoses", {
        "filters": args.filters,
        "fleetId": args.fleetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getFleetDiagnoses.
 */
export interface GetFleetDiagnosesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Jms.GetFleetDiagnosesFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     */
    fleetId: pulumi.Input<string>;
}
