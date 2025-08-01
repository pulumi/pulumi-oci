// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Fsu Cycle resource in Oracle Cloud Infrastructure Fleet Software Update service.
 *
 * Creates a new Exadata Fleet Update Cycle.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFsuCycle = new oci.fleetsoftwareupdate.FsuCycle("test_fsu_cycle", {
 *     compartmentId: compartmentId,
 *     fsuCollectionId: testFsuCollection.id,
 *     goalVersionDetails: {
 *         type: fsuCycleGoalVersionDetailsType,
 *         homePolicy: fsuCycleGoalVersionDetailsHomePolicy,
 *         newHomePrefix: fsuCycleGoalVersionDetailsNewHomePrefix,
 *         softwareImageId: testImage.id,
 *         version: fsuCycleGoalVersionDetailsVersion,
 *     },
 *     type: fsuCycleType,
 *     applyActionSchedule: {
 *         timeToStart: fsuCycleApplyActionScheduleTimeToStart,
 *         type: fsuCycleApplyActionScheduleType,
 *     },
 *     batchingStrategy: {
 *         isForceRolling: fsuCycleBatchingStrategyIsForceRolling,
 *         isWaitForBatchResume: fsuCycleBatchingStrategyIsWaitForBatchResume,
 *         percentage: fsuCycleBatchingStrategyPercentage,
 *         type: fsuCycleBatchingStrategyType,
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     diagnosticsCollection: {
 *         logCollectionMode: fsuCycleDiagnosticsCollectionLogCollectionMode,
 *     },
 *     displayName: fsuCycleDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     isIgnoreMissingPatches: fsuCycleIsIgnoreMissingPatches,
 *     isIgnorePatches: fsuCycleIsIgnorePatches,
 *     isKeepPlacement: fsuCycleIsKeepPlacement,
 *     maxDrainTimeoutInSeconds: fsuCycleMaxDrainTimeoutInSeconds,
 *     stageActionSchedule: {
 *         timeToStart: fsuCycleStageActionScheduleTimeToStart,
 *         type: fsuCycleStageActionScheduleType,
 *     },
 *     upgradeDetails: {
 *         collectionType: fsuCycleUpgradeDetailsCollectionType,
 *         isRecompileInvalidObjects: fsuCycleUpgradeDetailsIsRecompileInvalidObjects,
 *         isTimeZoneUpgrade: fsuCycleUpgradeDetailsIsTimeZoneUpgrade,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * FsuCycles can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:FleetSoftwareUpdate/fsuCycle:FsuCycle test_fsu_cycle "id"
 * ```
 */
export class FsuCycle extends pulumi.CustomResource {
    /**
     * Get an existing FsuCycle resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FsuCycleState, opts?: pulumi.CustomResourceOptions): FsuCycle {
        return new FsuCycle(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FleetSoftwareUpdate/fsuCycle:FsuCycle';

    /**
     * Returns true if the given object is an instance of FsuCycle.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FsuCycle {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FsuCycle.__pulumiType;
    }

    /**
     * Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
     */
    public readonly applyActionSchedule!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleApplyActionSchedule>;
    /**
     * (Updatable) Batching strategy details to use during PRECHECK and APPLY Cycle Actions.
     */
    public readonly batchingStrategy!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleBatchingStrategy>;
    /**
     * Type of Exadata Fleet Update collection being upgraded.
     */
    public /*out*/ readonly collectionType!: pulumi.Output<string>;
    /**
     * (Updatable) Compartment Identifier.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Details to configure diagnostics collection for targets affected by this Exadata Fleet Update Maintenance Cycle.
     */
    public readonly diagnosticsCollection!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleDiagnosticsCollection>;
    /**
     * (Updatable) Exadata Fleet Update Cycle display name.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * OCID identifier for the Action that is currently in execution, if applicable.
     */
    public /*out*/ readonly executingFsuActionId!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * OCID identifier for the Collection ID the Exadata Fleet Update Cycle will be assigned to.
     */
    public readonly fsuCollectionId!: pulumi.Output<string>;
    /**
     * (Updatable) Goal version or image details for the Exadata Fleet Update Cycle.
     */
    public readonly goalVersionDetails!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleGoalVersionDetails>;
    /**
     * (Updatable) List of patch IDs to ignore.
     */
    public readonly isIgnoreMissingPatches!: pulumi.Output<string[]>;
    /**
     * (Updatable) Ignore all patches between the source and target homes during patching.
     */
    public readonly isIgnorePatches!: pulumi.Output<boolean>;
    /**
     * (Updatable) Ensure that services of administrator-managed Oracle RAC or Oracle RAC One databases are running on the same instances before and after the move operation.
     */
    public readonly isKeepPlacement!: pulumi.Output<boolean>;
    /**
     * The latest Action type that was completed in the Exadata Fleet Update Cycle. No value would indicate that the Cycle has not completed any Action yet.
     */
    public /*out*/ readonly lastCompletedAction!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the latest Action  in the Exadata Fleet Update Cycle.
     */
    public /*out*/ readonly lastCompletedActionId!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Service drain timeout specified in seconds.
     */
    public readonly maxDrainTimeoutInSeconds!: pulumi.Output<number>;
    /**
     * In this array all the possible actions will be listed. The first element is the suggested Action.
     */
    public /*out*/ readonly nextActionToExecutes!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleNextActionToExecute[]>;
    /**
     * Current rollback cycle state if rollback maintenance cycle action has been attempted. No value would indicate that the Cycle has not run a rollback maintenance cycle action before.
     */
    public /*out*/ readonly rollbackCycleState!: pulumi.Output<string>;
    /**
     * Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
     */
    public readonly stageActionSchedule!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleStageActionSchedule>;
    /**
     * The current state of the Exadata Fleet Update Cycle.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the Exadata Fleet Update Cycle was created, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the Exadata Fleet Update Cycle was finished, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    public /*out*/ readonly timeFinished!: pulumi.Output<string>;
    /**
     * The date and time the Exadata Fleet Update Cycle was updated, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) Type of Exadata Fleet Update Cycle.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * (Updatable) Details of supported upgrade options for DB or GI collection.
     */
    public readonly upgradeDetails!: pulumi.Output<outputs.FleetSoftwareUpdate.FsuCycleUpgradeDetails>;

    /**
     * Create a FsuCycle resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FsuCycleArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FsuCycleArgs | FsuCycleState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FsuCycleState | undefined;
            resourceInputs["applyActionSchedule"] = state ? state.applyActionSchedule : undefined;
            resourceInputs["batchingStrategy"] = state ? state.batchingStrategy : undefined;
            resourceInputs["collectionType"] = state ? state.collectionType : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["diagnosticsCollection"] = state ? state.diagnosticsCollection : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["executingFsuActionId"] = state ? state.executingFsuActionId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["fsuCollectionId"] = state ? state.fsuCollectionId : undefined;
            resourceInputs["goalVersionDetails"] = state ? state.goalVersionDetails : undefined;
            resourceInputs["isIgnoreMissingPatches"] = state ? state.isIgnoreMissingPatches : undefined;
            resourceInputs["isIgnorePatches"] = state ? state.isIgnorePatches : undefined;
            resourceInputs["isKeepPlacement"] = state ? state.isKeepPlacement : undefined;
            resourceInputs["lastCompletedAction"] = state ? state.lastCompletedAction : undefined;
            resourceInputs["lastCompletedActionId"] = state ? state.lastCompletedActionId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["maxDrainTimeoutInSeconds"] = state ? state.maxDrainTimeoutInSeconds : undefined;
            resourceInputs["nextActionToExecutes"] = state ? state.nextActionToExecutes : undefined;
            resourceInputs["rollbackCycleState"] = state ? state.rollbackCycleState : undefined;
            resourceInputs["stageActionSchedule"] = state ? state.stageActionSchedule : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeFinished"] = state ? state.timeFinished : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["upgradeDetails"] = state ? state.upgradeDetails : undefined;
        } else {
            const args = argsOrState as FsuCycleArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.fsuCollectionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fsuCollectionId'");
            }
            if ((!args || args.goalVersionDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'goalVersionDetails'");
            }
            if ((!args || args.type === undefined) && !opts.urn) {
                throw new Error("Missing required property 'type'");
            }
            resourceInputs["applyActionSchedule"] = args ? args.applyActionSchedule : undefined;
            resourceInputs["batchingStrategy"] = args ? args.batchingStrategy : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["diagnosticsCollection"] = args ? args.diagnosticsCollection : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["fsuCollectionId"] = args ? args.fsuCollectionId : undefined;
            resourceInputs["goalVersionDetails"] = args ? args.goalVersionDetails : undefined;
            resourceInputs["isIgnoreMissingPatches"] = args ? args.isIgnoreMissingPatches : undefined;
            resourceInputs["isIgnorePatches"] = args ? args.isIgnorePatches : undefined;
            resourceInputs["isKeepPlacement"] = args ? args.isKeepPlacement : undefined;
            resourceInputs["maxDrainTimeoutInSeconds"] = args ? args.maxDrainTimeoutInSeconds : undefined;
            resourceInputs["stageActionSchedule"] = args ? args.stageActionSchedule : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["upgradeDetails"] = args ? args.upgradeDetails : undefined;
            resourceInputs["collectionType"] = undefined /*out*/;
            resourceInputs["executingFsuActionId"] = undefined /*out*/;
            resourceInputs["lastCompletedAction"] = undefined /*out*/;
            resourceInputs["lastCompletedActionId"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["nextActionToExecutes"] = undefined /*out*/;
            resourceInputs["rollbackCycleState"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeFinished"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(FsuCycle.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FsuCycle resources.
 */
export interface FsuCycleState {
    /**
     * Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
     */
    applyActionSchedule?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleApplyActionSchedule>;
    /**
     * (Updatable) Batching strategy details to use during PRECHECK and APPLY Cycle Actions.
     */
    batchingStrategy?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleBatchingStrategy>;
    /**
     * Type of Exadata Fleet Update collection being upgraded.
     */
    collectionType?: pulumi.Input<string>;
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Details to configure diagnostics collection for targets affected by this Exadata Fleet Update Maintenance Cycle.
     */
    diagnosticsCollection?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleDiagnosticsCollection>;
    /**
     * (Updatable) Exadata Fleet Update Cycle display name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * OCID identifier for the Action that is currently in execution, if applicable.
     */
    executingFsuActionId?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * OCID identifier for the Collection ID the Exadata Fleet Update Cycle will be assigned to.
     */
    fsuCollectionId?: pulumi.Input<string>;
    /**
     * (Updatable) Goal version or image details for the Exadata Fleet Update Cycle.
     */
    goalVersionDetails?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleGoalVersionDetails>;
    /**
     * (Updatable) List of patch IDs to ignore.
     */
    isIgnoreMissingPatches?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Ignore all patches between the source and target homes during patching.
     */
    isIgnorePatches?: pulumi.Input<boolean>;
    /**
     * (Updatable) Ensure that services of administrator-managed Oracle RAC or Oracle RAC One databases are running on the same instances before and after the move operation.
     */
    isKeepPlacement?: pulumi.Input<boolean>;
    /**
     * The latest Action type that was completed in the Exadata Fleet Update Cycle. No value would indicate that the Cycle has not completed any Action yet.
     */
    lastCompletedAction?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the latest Action  in the Exadata Fleet Update Cycle.
     */
    lastCompletedActionId?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Service drain timeout specified in seconds.
     */
    maxDrainTimeoutInSeconds?: pulumi.Input<number>;
    /**
     * In this array all the possible actions will be listed. The first element is the suggested Action.
     */
    nextActionToExecutes?: pulumi.Input<pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleNextActionToExecute>[]>;
    /**
     * Current rollback cycle state if rollback maintenance cycle action has been attempted. No value would indicate that the Cycle has not run a rollback maintenance cycle action before.
     */
    rollbackCycleState?: pulumi.Input<string>;
    /**
     * Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
     */
    stageActionSchedule?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleStageActionSchedule>;
    /**
     * The current state of the Exadata Fleet Update Cycle.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the Exadata Fleet Update Cycle was created, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the Exadata Fleet Update Cycle was finished, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    timeFinished?: pulumi.Input<string>;
    /**
     * The date and time the Exadata Fleet Update Cycle was updated, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) Type of Exadata Fleet Update Cycle.
     */
    type?: pulumi.Input<string>;
    /**
     * (Updatable) Details of supported upgrade options for DB or GI collection.
     */
    upgradeDetails?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleUpgradeDetails>;
}

/**
 * The set of arguments for constructing a FsuCycle resource.
 */
export interface FsuCycleArgs {
    /**
     * Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
     */
    applyActionSchedule?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleApplyActionSchedule>;
    /**
     * (Updatable) Batching strategy details to use during PRECHECK and APPLY Cycle Actions.
     */
    batchingStrategy?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleBatchingStrategy>;
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Details to configure diagnostics collection for targets affected by this Exadata Fleet Update Maintenance Cycle.
     */
    diagnosticsCollection?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleDiagnosticsCollection>;
    /**
     * (Updatable) Exadata Fleet Update Cycle display name.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * OCID identifier for the Collection ID the Exadata Fleet Update Cycle will be assigned to.
     */
    fsuCollectionId: pulumi.Input<string>;
    /**
     * (Updatable) Goal version or image details for the Exadata Fleet Update Cycle.
     */
    goalVersionDetails: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleGoalVersionDetails>;
    /**
     * (Updatable) List of patch IDs to ignore.
     */
    isIgnoreMissingPatches?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Ignore all patches between the source and target homes during patching.
     */
    isIgnorePatches?: pulumi.Input<boolean>;
    /**
     * (Updatable) Ensure that services of administrator-managed Oracle RAC or Oracle RAC One databases are running on the same instances before and after the move operation.
     */
    isKeepPlacement?: pulumi.Input<boolean>;
    /**
     * (Updatable) Service drain timeout specified in seconds.
     */
    maxDrainTimeoutInSeconds?: pulumi.Input<number>;
    /**
     * Scheduling related details for the Exadata Fleet Update Action during create operations. The specified time should not conflict with existing Exadata Infrastructure maintenance windows. Null scheduleDetails for Stage and Apply Actions in Exadata Fleet Update Cycle creation would not create Actions. Null scheduleDetails for CreateAction would execute the Exadata Fleet Update Action as soon as possible.
     */
    stageActionSchedule?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleStageActionSchedule>;
    /**
     * (Updatable) Type of Exadata Fleet Update Cycle.
     */
    type: pulumi.Input<string>;
    /**
     * (Updatable) Details of supported upgrade options for DB or GI collection.
     */
    upgradeDetails?: pulumi.Input<inputs.FleetSoftwareUpdate.FsuCycleUpgradeDetails>;
}
