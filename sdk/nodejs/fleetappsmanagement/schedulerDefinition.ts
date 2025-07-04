// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Scheduler Definition resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Create a SchedulerDefinition to perform lifecycle operations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedulerDefinition = new oci.fleetappsmanagement.SchedulerDefinition("test_scheduler_definition", {
 *     actionGroups: [{
 *         fleetId: testFleet.id,
 *         kind: schedulerDefinitionActionGroupsKind,
 *         runbookId: testRunbook.id,
 *         runbookVersionName: testRunbookVersion.name,
 *         displayName: schedulerDefinitionActionGroupsDisplayName,
 *         sequence: schedulerDefinitionActionGroupsSequence,
 *     }],
 *     compartmentId: compartmentId,
 *     schedule: {
 *         executionStartdate: schedulerDefinitionScheduleExecutionStartdate,
 *         type: schedulerDefinitionScheduleType,
 *         duration: schedulerDefinitionScheduleDuration,
 *         maintenanceWindowId: testMaintenanceWindow.id,
 *         recurrences: schedulerDefinitionScheduleRecurrences,
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     description: schedulerDefinitionDescription,
 *     displayName: schedulerDefinitionDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     runBooks: [{
 *         runbookId: testRunbook.id,
 *         runbookVersionName: testRunbookVersion.name,
 *         inputParameters: [{
 *             stepName: schedulerDefinitionRunBooksInputParametersStepName,
 *             arguments: [{
 *                 kind: schedulerDefinitionRunBooksInputParametersArgumentsKind,
 *                 name: schedulerDefinitionRunBooksInputParametersArgumentsName,
 *                 content: {
 *                     bucket: schedulerDefinitionRunBooksInputParametersArgumentsContentBucket,
 *                     checksum: schedulerDefinitionRunBooksInputParametersArgumentsContentChecksum,
 *                     namespace: schedulerDefinitionRunBooksInputParametersArgumentsContentNamespace,
 *                     object: schedulerDefinitionRunBooksInputParametersArgumentsContentObject,
 *                     sourceType: schedulerDefinitionRunBooksInputParametersArgumentsContentSourceType,
 *                 },
 *                 value: schedulerDefinitionRunBooksInputParametersArgumentsValue,
 *             }],
 *         }],
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * SchedulerDefinitions can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:FleetAppsManagement/schedulerDefinition:SchedulerDefinition test_scheduler_definition "id"
 * ```
 */
export class SchedulerDefinition extends pulumi.CustomResource {
    /**
     * Get an existing SchedulerDefinition resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SchedulerDefinitionState, opts?: pulumi.CustomResourceOptions): SchedulerDefinition {
        return new SchedulerDefinition(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FleetAppsManagement/schedulerDefinition:SchedulerDefinition';

    /**
     * Returns true if the given object is an instance of SchedulerDefinition.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SchedulerDefinition {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SchedulerDefinition.__pulumiType;
    }

    /**
     * (Updatable) Action Groups associated with the Schedule.
     */
    public readonly actionGroups!: pulumi.Output<outputs.FleetAppsManagement.SchedulerDefinitionActionGroup[]>;
    /**
     * Compartment OCID
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Count of Action Groups affected by the Schedule.
     */
    public /*out*/ readonly countOfAffectedActionGroups!: pulumi.Output<number>;
    /**
     * Count of Resources affected by the Schedule.
     */
    public /*out*/ readonly countOfAffectedResources!: pulumi.Output<number>;
    /**
     * Count of Targets affected by the Schedule.
     */
    public /*out*/ readonly countOfAffectedTargets!: pulumi.Output<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * All LifeCycle Operations that are part of the schedule.
     */
    public /*out*/ readonly lifecycleOperations!: pulumi.Output<string[]>;
    /**
     * All products that are part of the schedule for PRODUCT ActionGroup Type.
     */
    public /*out*/ readonly products!: pulumi.Output<string[]>;
    /**
     * Associated region
     */
    public /*out*/ readonly resourceRegion!: pulumi.Output<string>;
    /**
     * (Updatable) Runbooks.
     */
    public readonly runBooks!: pulumi.Output<outputs.FleetAppsManagement.SchedulerDefinitionRunBook[]>;
    /**
     * (Updatable) Schedule Information.
     */
    public readonly schedule!: pulumi.Output<outputs.FleetAppsManagement.SchedulerDefinitionSchedule>;
    /**
     * The current state of the SchedulerDefinition.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The scheduled date for the next run of the Job.
     */
    public /*out*/ readonly timeOfNextRun!: pulumi.Output<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a SchedulerDefinition resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SchedulerDefinitionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SchedulerDefinitionArgs | SchedulerDefinitionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SchedulerDefinitionState | undefined;
            resourceInputs["actionGroups"] = state ? state.actionGroups : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["countOfAffectedActionGroups"] = state ? state.countOfAffectedActionGroups : undefined;
            resourceInputs["countOfAffectedResources"] = state ? state.countOfAffectedResources : undefined;
            resourceInputs["countOfAffectedTargets"] = state ? state.countOfAffectedTargets : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["lifecycleOperations"] = state ? state.lifecycleOperations : undefined;
            resourceInputs["products"] = state ? state.products : undefined;
            resourceInputs["resourceRegion"] = state ? state.resourceRegion : undefined;
            resourceInputs["runBooks"] = state ? state.runBooks : undefined;
            resourceInputs["schedule"] = state ? state.schedule : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeOfNextRun"] = state ? state.timeOfNextRun : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as SchedulerDefinitionArgs | undefined;
            if ((!args || args.actionGroups === undefined) && !opts.urn) {
                throw new Error("Missing required property 'actionGroups'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.schedule === undefined) && !opts.urn) {
                throw new Error("Missing required property 'schedule'");
            }
            resourceInputs["actionGroups"] = args ? args.actionGroups : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["runBooks"] = args ? args.runBooks : undefined;
            resourceInputs["schedule"] = args ? args.schedule : undefined;
            resourceInputs["countOfAffectedActionGroups"] = undefined /*out*/;
            resourceInputs["countOfAffectedResources"] = undefined /*out*/;
            resourceInputs["countOfAffectedTargets"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["lifecycleOperations"] = undefined /*out*/;
            resourceInputs["products"] = undefined /*out*/;
            resourceInputs["resourceRegion"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeOfNextRun"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SchedulerDefinition.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SchedulerDefinition resources.
 */
export interface SchedulerDefinitionState {
    /**
     * (Updatable) Action Groups associated with the Schedule.
     */
    actionGroups?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.SchedulerDefinitionActionGroup>[]>;
    /**
     * Compartment OCID
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Count of Action Groups affected by the Schedule.
     */
    countOfAffectedActionGroups?: pulumi.Input<number>;
    /**
     * Count of Resources affected by the Schedule.
     */
    countOfAffectedResources?: pulumi.Input<number>;
    /**
     * Count of Targets affected by the Schedule.
     */
    countOfAffectedTargets?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * All LifeCycle Operations that are part of the schedule.
     */
    lifecycleOperations?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * All products that are part of the schedule for PRODUCT ActionGroup Type.
     */
    products?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Associated region
     */
    resourceRegion?: pulumi.Input<string>;
    /**
     * (Updatable) Runbooks.
     */
    runBooks?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.SchedulerDefinitionRunBook>[]>;
    /**
     * (Updatable) Schedule Information.
     */
    schedule?: pulumi.Input<inputs.FleetAppsManagement.SchedulerDefinitionSchedule>;
    /**
     * The current state of the SchedulerDefinition.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The scheduled date for the next run of the Job.
     */
    timeOfNextRun?: pulumi.Input<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SchedulerDefinition resource.
 */
export interface SchedulerDefinitionArgs {
    /**
     * (Updatable) Action Groups associated with the Schedule.
     */
    actionGroups: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.SchedulerDefinitionActionGroup>[]>;
    /**
     * Compartment OCID
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Runbooks.
     */
    runBooks?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.SchedulerDefinitionRunBook>[]>;
    /**
     * (Updatable) Schedule Information.
     */
    schedule: pulumi.Input<inputs.FleetAppsManagement.SchedulerDefinitionSchedule>;
}
