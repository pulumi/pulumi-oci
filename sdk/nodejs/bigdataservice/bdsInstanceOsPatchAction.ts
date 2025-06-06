// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Bds Instance OS Patch Action resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Install the specified OS patch to this cluster nodes.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstanceOsPatchAction = new oci.bigdataservice.BdsInstanceOsPatchAction("test_bds_instance_os_patch_action", {
 *     bdsInstanceId: testBdsInstance.id,
 *     clusterAdminPassword: bdsInstanceOsPatchActionClusterAdminPassword,
 *     osPatchVersion: bdsInstanceOsPatchActionOsPatchVersion,
 *     isDryRun: isDryRun,
 *     patchingConfigs: {
 *         patchingConfigStrategy: bdsInstanceOsPatchActionPatchingConfigStrategy,
 *         batchSize: bdsInstanceOsPatchActionBatchSize,
 *         waitTimeBetweenBatchInSeconds: bdsInstanceOsPatchActionWaitTimeBetweenBatchInSeconds,
 *         toleranceThresholdPerBatch: bdsInstanceOsPatchActionToleranceThresholdPerBatch,
 *         waitTimeBetweenDomainInSeconds: bdsInstanceOsPatchActionWaitTimeBetweenDomainInSeconds,
 *         toleranceThresholdPerDomain: bdsInstanceOsPatchActionToleranceThresholdPerDomain,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class BdsInstanceOsPatchAction extends pulumi.CustomResource {
    /**
     * Get an existing BdsInstanceOsPatchAction resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: BdsInstanceOsPatchActionState, opts?: pulumi.CustomResourceOptions): BdsInstanceOsPatchAction {
        return new BdsInstanceOsPatchAction(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:BigDataService/bdsInstanceOsPatchAction:BdsInstanceOsPatchAction';

    /**
     * Returns true if the given object is an instance of BdsInstanceOsPatchAction.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is BdsInstanceOsPatchAction {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === BdsInstanceOsPatchAction.__pulumiType;
    }

    /**
     * The OCID of the cluster.
     */
    public readonly bdsInstanceId!: pulumi.Output<string>;
    /**
     * Base-64 encoded password for the cluster admin user.
     * * `isDryRun` - (Optional) Perform dry run for the patch and stop without actually patching the cluster.
     */
    public readonly clusterAdminPassword!: pulumi.Output<string>;
    public readonly isDryRun!: pulumi.Output<boolean | undefined>;
    /**
     * The version of the OS patch to be installed.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly osPatchVersion!: pulumi.Output<string>;
    /**
     * Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     */
    public readonly patchingConfigs!: pulumi.Output<outputs.BigDataService.BdsInstanceOsPatchActionPatchingConfigs>;

    /**
     * Create a BdsInstanceOsPatchAction resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: BdsInstanceOsPatchActionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: BdsInstanceOsPatchActionArgs | BdsInstanceOsPatchActionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as BdsInstanceOsPatchActionState | undefined;
            resourceInputs["bdsInstanceId"] = state ? state.bdsInstanceId : undefined;
            resourceInputs["clusterAdminPassword"] = state ? state.clusterAdminPassword : undefined;
            resourceInputs["isDryRun"] = state ? state.isDryRun : undefined;
            resourceInputs["osPatchVersion"] = state ? state.osPatchVersion : undefined;
            resourceInputs["patchingConfigs"] = state ? state.patchingConfigs : undefined;
        } else {
            const args = argsOrState as BdsInstanceOsPatchActionArgs | undefined;
            if ((!args || args.bdsInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'bdsInstanceId'");
            }
            if ((!args || args.clusterAdminPassword === undefined) && !opts.urn) {
                throw new Error("Missing required property 'clusterAdminPassword'");
            }
            if ((!args || args.osPatchVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'osPatchVersion'");
            }
            resourceInputs["bdsInstanceId"] = args ? args.bdsInstanceId : undefined;
            resourceInputs["clusterAdminPassword"] = args?.clusterAdminPassword ? pulumi.secret(args.clusterAdminPassword) : undefined;
            resourceInputs["isDryRun"] = args ? args.isDryRun : undefined;
            resourceInputs["osPatchVersion"] = args ? args.osPatchVersion : undefined;
            resourceInputs["patchingConfigs"] = args ? args.patchingConfigs : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        const secretOpts = { additionalSecretOutputs: ["clusterAdminPassword"] };
        opts = pulumi.mergeOptions(opts, secretOpts);
        super(BdsInstanceOsPatchAction.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering BdsInstanceOsPatchAction resources.
 */
export interface BdsInstanceOsPatchActionState {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId?: pulumi.Input<string>;
    /**
     * Base-64 encoded password for the cluster admin user.
     * * `isDryRun` - (Optional) Perform dry run for the patch and stop without actually patching the cluster.
     */
    clusterAdminPassword?: pulumi.Input<string>;
    isDryRun?: pulumi.Input<boolean>;
    /**
     * The version of the OS patch to be installed.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    osPatchVersion?: pulumi.Input<string>;
    /**
     * Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     */
    patchingConfigs?: pulumi.Input<inputs.BigDataService.BdsInstanceOsPatchActionPatchingConfigs>;
}

/**
 * The set of arguments for constructing a BdsInstanceOsPatchAction resource.
 */
export interface BdsInstanceOsPatchActionArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: pulumi.Input<string>;
    /**
     * Base-64 encoded password for the cluster admin user.
     * * `isDryRun` - (Optional) Perform dry run for the patch and stop without actually patching the cluster.
     */
    clusterAdminPassword: pulumi.Input<string>;
    isDryRun?: pulumi.Input<boolean>;
    /**
     * The version of the OS patch to be installed.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    osPatchVersion: pulumi.Input<string>;
    /**
     * Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     */
    patchingConfigs?: pulumi.Input<inputs.BigDataService.BdsInstanceOsPatchActionPatchingConfigs>;
}
