// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Model Version Sets in Oracle Cloud Infrastructure Data Science service.
 *
 * Lists model version sets in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelVersionSets = oci.DataScience.getModelVersionSets({
 *     compartmentId: _var.compartment_id,
 *     createdBy: _var.model_version_set_created_by,
 *     id: _var.model_version_set_id,
 *     name: _var.model_version_set_name,
 *     projectId: oci_datascience_project.test_project.id,
 *     state: _var.model_version_set_state,
 * });
 * ```
 */
export function getModelVersionSets(args: GetModelVersionSetsArgs, opts?: pulumi.InvokeOptions): Promise<GetModelVersionSetsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataScience/getModelVersionSets:getModelVersionSets", {
        "compartmentId": args.compartmentId,
        "createdBy": args.createdBy,
        "filters": args.filters,
        "id": args.id,
        "name": args.name,
        "projectId": args.projectId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getModelVersionSets.
 */
export interface GetModelVersionSetsArgs {
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     */
    createdBy?: string;
    filters?: inputs.DataScience.GetModelVersionSetsFilter[];
    /**
     * <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
     */
    id?: string;
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: string;
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
     */
    projectId?: string;
    /**
     * <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: string;
}

/**
 * A collection of values returned by getModelVersionSets.
 */
export interface GetModelVersionSetsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set compartment.
     */
    readonly compartmentId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model version set.
     */
    readonly createdBy?: string;
    readonly filters?: outputs.DataScience.GetModelVersionSetsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
     */
    readonly id?: string;
    /**
     * The list of model_version_sets.
     */
    readonly modelVersionSets: outputs.DataScience.GetModelVersionSetsModelVersionSet[];
    /**
     * A user-friendly name for the resource. It must be unique and can't be modified.
     */
    readonly name?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model version set.
     */
    readonly projectId?: string;
    /**
     * The state of the model version set.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Model Version Sets in Oracle Cloud Infrastructure Data Science service.
 *
 * Lists model version sets in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelVersionSets = oci.DataScience.getModelVersionSets({
 *     compartmentId: _var.compartment_id,
 *     createdBy: _var.model_version_set_created_by,
 *     id: _var.model_version_set_id,
 *     name: _var.model_version_set_name,
 *     projectId: oci_datascience_project.test_project.id,
 *     state: _var.model_version_set_state,
 * });
 * ```
 */
export function getModelVersionSetsOutput(args: GetModelVersionSetsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetModelVersionSetsResult> {
    return pulumi.output(args).apply((a: any) => getModelVersionSets(a, opts))
}

/**
 * A collection of arguments for invoking getModelVersionSets.
 */
export interface GetModelVersionSetsOutputArgs {
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     */
    createdBy?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataScience.GetModelVersionSetsFilterArgs>[]>;
    /**
     * <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
     */
    projectId?: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: pulumi.Input<string>;
}