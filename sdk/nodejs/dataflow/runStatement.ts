// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Run Statement resource in Oracle Cloud Infrastructure Data Flow service.
 *
 * Executes a statement for a Session run.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRunStatement = new oci.dataflow.RunStatement("testRunStatement", {
 *     code: _var.run_statement_code,
 *     runId: oci_dataflow_run.test_run.id,
 * });
 * ```
 *
 * ## Import
 *
 * RunStatements can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DataFlow/runStatement:RunStatement test_run_statement "runs/{runId}/statements/{statementId}"
 * ```
 */
export class RunStatement extends pulumi.CustomResource {
    /**
     * Get an existing RunStatement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: RunStatementState, opts?: pulumi.CustomResourceOptions): RunStatement {
        return new RunStatement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataFlow/runStatement:RunStatement';

    /**
     * Returns true if the given object is an instance of RunStatement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is RunStatement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === RunStatement.__pulumiType;
    }

    /**
     * The statement code to execute. Example: `println(sc.version)`
     */
    public readonly code!: pulumi.Output<string>;
    /**
     * The execution output of a statement.
     */
    public /*out*/ readonly outputs!: pulumi.Output<outputs.DataFlow.RunStatementOutput[]>;
    /**
     * The execution progress.
     */
    public /*out*/ readonly progress!: pulumi.Output<number>;
    /**
     * The unique ID for the run
     */
    public readonly runId!: pulumi.Output<string>;
    /**
     * The current state of this statement.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time a statement execution was completed, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2022-05-31T21:10:29.600Z`
     */
    public /*out*/ readonly timeCompleted!: pulumi.Output<string>;
    /**
     * The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a RunStatement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: RunStatementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: RunStatementArgs | RunStatementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as RunStatementState | undefined;
            resourceInputs["code"] = state ? state.code : undefined;
            resourceInputs["outputs"] = state ? state.outputs : undefined;
            resourceInputs["progress"] = state ? state.progress : undefined;
            resourceInputs["runId"] = state ? state.runId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCompleted"] = state ? state.timeCompleted : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as RunStatementArgs | undefined;
            if ((!args || args.code === undefined) && !opts.urn) {
                throw new Error("Missing required property 'code'");
            }
            if ((!args || args.runId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'runId'");
            }
            resourceInputs["code"] = args ? args.code : undefined;
            resourceInputs["runId"] = args ? args.runId : undefined;
            resourceInputs["outputs"] = undefined /*out*/;
            resourceInputs["progress"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCompleted"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(RunStatement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering RunStatement resources.
 */
export interface RunStatementState {
    /**
     * The statement code to execute. Example: `println(sc.version)`
     */
    code?: pulumi.Input<string>;
    /**
     * The execution output of a statement.
     */
    outputs?: pulumi.Input<pulumi.Input<inputs.DataFlow.RunStatementOutput>[]>;
    /**
     * The execution progress.
     */
    progress?: pulumi.Input<number>;
    /**
     * The unique ID for the run
     */
    runId?: pulumi.Input<string>;
    /**
     * The current state of this statement.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time a statement execution was completed, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2022-05-31T21:10:29.600Z`
     */
    timeCompleted?: pulumi.Input<string>;
    /**
     * The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a RunStatement resource.
 */
export interface RunStatementArgs {
    /**
     * The statement code to execute. Example: `println(sc.version)`
     */
    code: pulumi.Input<string>;
    /**
     * The unique ID for the run
     */
    runId: pulumi.Input<string>;
}