// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Fusion Environment Refresh Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Creates a new RefreshActivity.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentRefreshActivity = new oci.fusionapps.FusionEnvironmentRefreshActivity("testFusionEnvironmentRefreshActivity", {
 *     fusionEnvironmentId: oci_fusion_apps_fusion_environment.test_fusion_environment.id,
 *     sourceFusionEnvironmentId: oci_fusion_apps_fusion_environment.test_fusion_environment.id,
 * });
 * ```
 *
 * ## Import
 *
 * FusionEnvironmentRefreshActivities can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity test_fusion_environment_refresh_activity "fusionEnvironments/{fusionEnvironmentId}/refreshActivities/{refreshActivityId}"
 * ```
 */
export class FusionEnvironmentRefreshActivity extends pulumi.CustomResource {
    /**
     * Get an existing FusionEnvironmentRefreshActivity resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FusionEnvironmentRefreshActivityState, opts?: pulumi.CustomResourceOptions): FusionEnvironmentRefreshActivity {
        return new FusionEnvironmentRefreshActivity(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity';

    /**
     * Returns true if the given object is an instance of FusionEnvironmentRefreshActivity.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FusionEnvironmentRefreshActivity {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FusionEnvironmentRefreshActivity.__pulumiType;
    }

    /**
     * A friendly name for the refresh activity. Can be changed later.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * unique FusionEnvironment identifier
     */
    public readonly fusionEnvironmentId!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Service availability / impact during refresh activity execution up down
     */
    public /*out*/ readonly serviceAvailability!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     */
    public readonly sourceFusionEnvironmentId!: pulumi.Output<string>;
    /**
     * The current state of the refreshActivity.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time the refresh activity record was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeAccepted!: pulumi.Output<string>;
    /**
     * The time the refresh activity is scheduled to end. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeExpectedFinish!: pulumi.Output<string>;
    /**
     * The time the refresh activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeFinished!: pulumi.Output<string>;
    /**
     * The date and time of the most recent source environment backup used for the environment refresh.
     */
    public /*out*/ readonly timeOfRestorationPoint!: pulumi.Output<string>;
    /**
     * The time the refresh activity is scheduled to start. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeScheduledStart!: pulumi.Output<string>;
    /**
     * The time the refresh activity record was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a FusionEnvironmentRefreshActivity resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FusionEnvironmentRefreshActivityArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FusionEnvironmentRefreshActivityArgs | FusionEnvironmentRefreshActivityState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FusionEnvironmentRefreshActivityState | undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["fusionEnvironmentId"] = state ? state.fusionEnvironmentId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["serviceAvailability"] = state ? state.serviceAvailability : undefined;
            resourceInputs["sourceFusionEnvironmentId"] = state ? state.sourceFusionEnvironmentId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeAccepted"] = state ? state.timeAccepted : undefined;
            resourceInputs["timeExpectedFinish"] = state ? state.timeExpectedFinish : undefined;
            resourceInputs["timeFinished"] = state ? state.timeFinished : undefined;
            resourceInputs["timeOfRestorationPoint"] = state ? state.timeOfRestorationPoint : undefined;
            resourceInputs["timeScheduledStart"] = state ? state.timeScheduledStart : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as FusionEnvironmentRefreshActivityArgs | undefined;
            if ((!args || args.fusionEnvironmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fusionEnvironmentId'");
            }
            if ((!args || args.sourceFusionEnvironmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sourceFusionEnvironmentId'");
            }
            resourceInputs["fusionEnvironmentId"] = args ? args.fusionEnvironmentId : undefined;
            resourceInputs["sourceFusionEnvironmentId"] = args ? args.sourceFusionEnvironmentId : undefined;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["serviceAvailability"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeAccepted"] = undefined /*out*/;
            resourceInputs["timeExpectedFinish"] = undefined /*out*/;
            resourceInputs["timeFinished"] = undefined /*out*/;
            resourceInputs["timeOfRestorationPoint"] = undefined /*out*/;
            resourceInputs["timeScheduledStart"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(FusionEnvironmentRefreshActivity.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FusionEnvironmentRefreshActivity resources.
 */
export interface FusionEnvironmentRefreshActivityState {
    /**
     * A friendly name for the refresh activity. Can be changed later.
     */
    displayName?: pulumi.Input<string>;
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Service availability / impact during refresh activity execution up down
     */
    serviceAvailability?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     */
    sourceFusionEnvironmentId?: pulumi.Input<string>;
    /**
     * The current state of the refreshActivity.
     */
    state?: pulumi.Input<string>;
    /**
     * The time the refresh activity record was created. An RFC3339 formatted datetime string.
     */
    timeAccepted?: pulumi.Input<string>;
    /**
     * The time the refresh activity is scheduled to end. An RFC3339 formatted datetime string.
     */
    timeExpectedFinish?: pulumi.Input<string>;
    /**
     * The time the refresh activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
     */
    timeFinished?: pulumi.Input<string>;
    /**
     * The date and time of the most recent source environment backup used for the environment refresh.
     */
    timeOfRestorationPoint?: pulumi.Input<string>;
    /**
     * The time the refresh activity is scheduled to start. An RFC3339 formatted datetime string.
     */
    timeScheduledStart?: pulumi.Input<string>;
    /**
     * The time the refresh activity record was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a FusionEnvironmentRefreshActivity resource.
 */
export interface FusionEnvironmentRefreshActivityArgs {
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     */
    sourceFusionEnvironmentId: pulumi.Input<string>;
}