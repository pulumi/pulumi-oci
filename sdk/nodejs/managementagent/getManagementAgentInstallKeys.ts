// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Management Agent Install Keys in Oracle Cloud Infrastructure Management Agent service.
 *
 * Returns a list of Management Agent installed Keys.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgentInstallKeys = oci.ManagementAgent.getManagementAgentInstallKeys({
 *     compartmentId: _var.compartment_id,
 *     accessLevel: _var.management_agent_install_key_access_level,
 *     compartmentIdInSubtree: _var.management_agent_install_key_compartment_id_in_subtree,
 *     displayName: _var.management_agent_install_key_display_name,
 *     state: _var.management_agent_install_key_state,
 * });
 * ```
 */
export function getManagementAgentInstallKeys(args: GetManagementAgentInstallKeysArgs, opts?: pulumi.InvokeOptions): Promise<GetManagementAgentInstallKeysResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ManagementAgent/getManagementAgentInstallKeys:getManagementAgentInstallKeys", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgentInstallKeys.
 */
export interface GetManagementAgentInstallKeysArgs {
    /**
     * Value of this is always "ACCESSIBLE" and any other value is not supported.
     */
    accessLevel?: string;
    /**
     * The OCID of the compartment to which a request will be scoped.
     */
    compartmentId: string;
    /**
     * if set to true then it fetches resources for all compartments where user has access to else only on the compartment specified.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * The display name for which the Key needs to be listed.
     */
    displayName?: string;
    filters?: inputs.ManagementAgent.GetManagementAgentInstallKeysFilter[];
    /**
     * Filter to return only Management Agents in the particular lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getManagementAgentInstallKeys.
 */
export interface GetManagementAgentInstallKeysResult {
    readonly accessLevel?: string;
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * Management Agent Install Key Name
     */
    readonly displayName?: string;
    readonly filters?: outputs.ManagementAgent.GetManagementAgentInstallKeysFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of management_agent_install_keys.
     */
    readonly managementAgentInstallKeys: outputs.ManagementAgent.GetManagementAgentInstallKeysManagementAgentInstallKey[];
    /**
     * Status of Key
     */
    readonly state?: string;
}

export function getManagementAgentInstallKeysOutput(args: GetManagementAgentInstallKeysOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagementAgentInstallKeysResult> {
    return pulumi.output(args).apply(a => getManagementAgentInstallKeys(a, opts))
}

/**
 * A collection of arguments for invoking getManagementAgentInstallKeys.
 */
export interface GetManagementAgentInstallKeysOutputArgs {
    /**
     * Value of this is always "ACCESSIBLE" and any other value is not supported.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * The OCID of the compartment to which a request will be scoped.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * if set to true then it fetches resources for all compartments where user has access to else only on the compartment specified.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * The display name for which the Key needs to be listed.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ManagementAgent.GetManagementAgentInstallKeysFilterArgs>[]>;
    /**
     * Filter to return only Management Agents in the particular lifecycle state.
     */
    state?: pulumi.Input<string>;
}