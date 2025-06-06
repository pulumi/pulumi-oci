// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Steering Policy resource in Oracle Cloud Infrastructure DNS service.
 *
 * Creates a new steering policy in the specified compartment. For more information on
 * creating policies with templates, see [Traffic Management API Guide](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Concepts/trafficmanagementapi.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSteeringPolicy = new oci.dns.SteeringPolicy("test_steering_policy", {
 *     compartmentId: compartmentId,
 *     displayName: steeringPolicyDisplayName,
 *     template: steeringPolicyTemplate,
 *     answers: [{
 *         name: steeringPolicyAnswersName,
 *         rdata: steeringPolicyAnswersRdata,
 *         rtype: steeringPolicyAnswersRtype,
 *         isDisabled: steeringPolicyAnswersIsDisabled,
 *         pool: steeringPolicyAnswersPool,
 *     }],
 *     definedTags: steeringPolicyDefinedTags,
 *     freeformTags: steeringPolicyFreeformTags,
 *     healthCheckMonitorId: testHttpMonitor.id,
 *     rules: [{
 *         ruleType: steeringPolicyRulesRuleType,
 *         cases: [{
 *             answerDatas: [{
 *                 answerCondition: steeringPolicyRulesCasesAnswerDataAnswerCondition,
 *                 shouldKeep: steeringPolicyRulesCasesAnswerDataShouldKeep,
 *                 value: steeringPolicyRulesCasesAnswerDataValue,
 *             }],
 *             caseCondition: steeringPolicyRulesCasesCaseCondition,
 *             count: steeringPolicyRulesCasesCount,
 *         }],
 *         defaultAnswerDatas: [{
 *             answerCondition: steeringPolicyRulesDefaultAnswerDataAnswerCondition,
 *             shouldKeep: steeringPolicyRulesDefaultAnswerDataShouldKeep,
 *             value: steeringPolicyRulesDefaultAnswerDataValue,
 *         }],
 *         defaultCount: steeringPolicyRulesDefaultCount,
 *         description: steeringPolicyRulesDescription,
 *     }],
 *     ttl: steeringPolicyTtl,
 * });
 * ```
 *
 * ## Import
 *
 * SteeringPolicies can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Dns/steeringPolicy:SteeringPolicy test_steering_policy "id"
 * ```
 */
export class SteeringPolicy extends pulumi.CustomResource {
    /**
     * Get an existing SteeringPolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SteeringPolicyState, opts?: pulumi.CustomResourceOptions): SteeringPolicy {
        return new SteeringPolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Dns/steeringPolicy:SteeringPolicy';

    /**
     * Returns true if the given object is an instance of SteeringPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SteeringPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SteeringPolicy.__pulumiType;
    }

    /**
     * The set of all answers that can potentially issue from the steering policy.
     */
    public readonly answers!: pulumi.Output<outputs.Dns.SteeringPolicyAnswer[]>;
    /**
     * (Updatable) The OCID of the compartment containing the steering policy.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     *
     * **Note:** To use the Health Check monitoring feature in a steering policy, a monitor must be created using the Health Checks service first. For more information on how to create a monitor, please see [Managing Health Checks](https://docs.cloud.oracle.com/iaas/Content/HealthChecks/Tasks/managinghealthchecks.htm).
     */
    public readonly healthCheckMonitorId!: pulumi.Output<string>;
    /**
     * The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     *
     * The first rule receives a shuffled list of all answers, and every other rule receives the list of answers emitted by the one preceding it. The last rule populates the response.
     */
    public readonly rules!: pulumi.Output<outputs.Dns.SteeringPolicyRule[]>;
    /**
     * The canonical absolute URL of the resource.
     */
    public /*out*/ readonly self!: pulumi.Output<string>;
    /**
     * The current state of the resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management's rules in a different order to produce the desired results when answering DNS queries.
     *
     * **Example:** The `FAILOVER` template determines answers by filtering the policy's answers using the `FILTER` rule first, then the following rules in succession: `HEALTH`, `PRIORITY`, and `LIMIT`. This gives the domain dynamic failover capability.
     *
     * It is **strongly recommended** to use a template other than `CUSTOM` when creating a steering policy.
     *
     * All templates require the rule order to begin with an unconditional `FILTER` rule that keeps answers contingent upon `answer.isDisabled != true`, except for `CUSTOM`. A defined `HEALTH` rule must follow the `FILTER` rule if the policy references a `healthCheckMonitorId`. The last rule of a template must must be a `LIMIT` rule. For more information about templates and code examples, see [Traffic Management API Guide](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Concepts/trafficmanagementapi.htm).
     *
     * **Template Types**
     * * `FAILOVER` - Uses health check information on your endpoints to determine which DNS answers to serve. If an endpoint fails a health check, the answer for that endpoint will be removed from the list of available answers until the endpoint is detected as healthy.
     * * `LOAD_BALANCE` - Distributes web traffic to specified endpoints based on defined weights.
     * * `ROUTE_BY_GEO` - Answers DNS queries based on the query's geographic location. For a list of geographic locations to route by, see [Traffic Management Geographic Locations](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Reference/trafficmanagementgeo.htm).
     * * `ROUTE_BY_ASN` - Answers DNS queries based on the query's originating ASN.
     * * `ROUTE_BY_IP` - Answers DNS queries based on the query's IP address.
     * * `CUSTOM` - Allows a customized configuration of rules.
     */
    public readonly template!: pulumi.Output<string>;
    /**
     * The date and time the resource was created, expressed in RFC 3339 timestamp format.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly ttl!: pulumi.Output<number>;

    /**
     * Create a SteeringPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SteeringPolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SteeringPolicyArgs | SteeringPolicyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SteeringPolicyState | undefined;
            resourceInputs["answers"] = state ? state.answers : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["healthCheckMonitorId"] = state ? state.healthCheckMonitorId : undefined;
            resourceInputs["rules"] = state ? state.rules : undefined;
            resourceInputs["self"] = state ? state.self : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["template"] = state ? state.template : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["ttl"] = state ? state.ttl : undefined;
        } else {
            const args = argsOrState as SteeringPolicyArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.template === undefined) && !opts.urn) {
                throw new Error("Missing required property 'template'");
            }
            resourceInputs["answers"] = args ? args.answers : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["healthCheckMonitorId"] = args ? args.healthCheckMonitorId : undefined;
            resourceInputs["rules"] = args ? args.rules : undefined;
            resourceInputs["template"] = args ? args.template : undefined;
            resourceInputs["ttl"] = args ? args.ttl : undefined;
            resourceInputs["self"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SteeringPolicy.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SteeringPolicy resources.
 */
export interface SteeringPolicyState {
    /**
     * The set of all answers that can potentially issue from the steering policy.
     */
    answers?: pulumi.Input<pulumi.Input<inputs.Dns.SteeringPolicyAnswer>[]>;
    /**
     * (Updatable) The OCID of the compartment containing the steering policy.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     *
     * **Note:** To use the Health Check monitoring feature in a steering policy, a monitor must be created using the Health Checks service first. For more information on how to create a monitor, please see [Managing Health Checks](https://docs.cloud.oracle.com/iaas/Content/HealthChecks/Tasks/managinghealthchecks.htm).
     */
    healthCheckMonitorId?: pulumi.Input<string>;
    /**
     * The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     *
     * The first rule receives a shuffled list of all answers, and every other rule receives the list of answers emitted by the one preceding it. The last rule populates the response.
     */
    rules?: pulumi.Input<pulumi.Input<inputs.Dns.SteeringPolicyRule>[]>;
    /**
     * The canonical absolute URL of the resource.
     */
    self?: pulumi.Input<string>;
    /**
     * The current state of the resource.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management's rules in a different order to produce the desired results when answering DNS queries.
     *
     * **Example:** The `FAILOVER` template determines answers by filtering the policy's answers using the `FILTER` rule first, then the following rules in succession: `HEALTH`, `PRIORITY`, and `LIMIT`. This gives the domain dynamic failover capability.
     *
     * It is **strongly recommended** to use a template other than `CUSTOM` when creating a steering policy.
     *
     * All templates require the rule order to begin with an unconditional `FILTER` rule that keeps answers contingent upon `answer.isDisabled != true`, except for `CUSTOM`. A defined `HEALTH` rule must follow the `FILTER` rule if the policy references a `healthCheckMonitorId`. The last rule of a template must must be a `LIMIT` rule. For more information about templates and code examples, see [Traffic Management API Guide](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Concepts/trafficmanagementapi.htm).
     *
     * **Template Types**
     * * `FAILOVER` - Uses health check information on your endpoints to determine which DNS answers to serve. If an endpoint fails a health check, the answer for that endpoint will be removed from the list of available answers until the endpoint is detected as healthy.
     * * `LOAD_BALANCE` - Distributes web traffic to specified endpoints based on defined weights.
     * * `ROUTE_BY_GEO` - Answers DNS queries based on the query's geographic location. For a list of geographic locations to route by, see [Traffic Management Geographic Locations](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Reference/trafficmanagementgeo.htm).
     * * `ROUTE_BY_ASN` - Answers DNS queries based on the query's originating ASN.
     * * `ROUTE_BY_IP` - Answers DNS queries based on the query's IP address.
     * * `CUSTOM` - Allows a customized configuration of rules.
     */
    template?: pulumi.Input<string>;
    /**
     * The date and time the resource was created, expressed in RFC 3339 timestamp format.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    ttl?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a SteeringPolicy resource.
 */
export interface SteeringPolicyArgs {
    /**
     * The set of all answers that can potentially issue from the steering policy.
     */
    answers?: pulumi.Input<pulumi.Input<inputs.Dns.SteeringPolicyAnswer>[]>;
    /**
     * (Updatable) The OCID of the compartment containing the steering policy.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     *
     * **Note:** To use the Health Check monitoring feature in a steering policy, a monitor must be created using the Health Checks service first. For more information on how to create a monitor, please see [Managing Health Checks](https://docs.cloud.oracle.com/iaas/Content/HealthChecks/Tasks/managinghealthchecks.htm).
     */
    healthCheckMonitorId?: pulumi.Input<string>;
    /**
     * The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     *
     * The first rule receives a shuffled list of all answers, and every other rule receives the list of answers emitted by the one preceding it. The last rule populates the response.
     */
    rules?: pulumi.Input<pulumi.Input<inputs.Dns.SteeringPolicyRule>[]>;
    /**
     * (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management's rules in a different order to produce the desired results when answering DNS queries.
     *
     * **Example:** The `FAILOVER` template determines answers by filtering the policy's answers using the `FILTER` rule first, then the following rules in succession: `HEALTH`, `PRIORITY`, and `LIMIT`. This gives the domain dynamic failover capability.
     *
     * It is **strongly recommended** to use a template other than `CUSTOM` when creating a steering policy.
     *
     * All templates require the rule order to begin with an unconditional `FILTER` rule that keeps answers contingent upon `answer.isDisabled != true`, except for `CUSTOM`. A defined `HEALTH` rule must follow the `FILTER` rule if the policy references a `healthCheckMonitorId`. The last rule of a template must must be a `LIMIT` rule. For more information about templates and code examples, see [Traffic Management API Guide](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Concepts/trafficmanagementapi.htm).
     *
     * **Template Types**
     * * `FAILOVER` - Uses health check information on your endpoints to determine which DNS answers to serve. If an endpoint fails a health check, the answer for that endpoint will be removed from the list of available answers until the endpoint is detected as healthy.
     * * `LOAD_BALANCE` - Distributes web traffic to specified endpoints based on defined weights.
     * * `ROUTE_BY_GEO` - Answers DNS queries based on the query's geographic location. For a list of geographic locations to route by, see [Traffic Management Geographic Locations](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Reference/trafficmanagementgeo.htm).
     * * `ROUTE_BY_ASN` - Answers DNS queries based on the query's originating ASN.
     * * `ROUTE_BY_IP` - Answers DNS queries based on the query's IP address.
     * * `CUSTOM` - Allows a customized configuration of rules.
     */
    template: pulumi.Input<string>;
    /**
     * (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    ttl?: pulumi.Input<number>;
}
