// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Dns.SteeringPolicyArgs;
import com.pulumi.oci.Dns.inputs.SteeringPolicyState;
import com.pulumi.oci.Dns.outputs.SteeringPolicyAnswer;
import com.pulumi.oci.Dns.outputs.SteeringPolicyRule;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Steering Policy resource in Oracle Cloud Infrastructure DNS service.
 * 
 * Creates a new steering policy in the specified compartment. For more information on
 * creating policies with templates, see [Traffic Management API Guide](https://docs.cloud.oracle.com/iaas/Content/TrafficManagement/Concepts/trafficmanagementapi.htm).
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * SteeringPolicies can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Dns/steeringPolicy:SteeringPolicy test_steering_policy &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Dns/steeringPolicy:SteeringPolicy")
public class SteeringPolicy extends com.pulumi.resources.CustomResource {
    /**
     * The set of all answers that can potentially issue from the steering policy.
     * 
     */
    @Export(name="answers", type=List.class, parameters={SteeringPolicyAnswer.class})
    private Output<List<SteeringPolicyAnswer>> answers;

    /**
     * @return The set of all answers that can potentially issue from the steering policy.
     * 
     */
    public Output<List<SteeringPolicyAnswer>> answers() {
        return this.answers;
    }
    /**
     * (Updatable) The OCID of the compartment containing the steering policy.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing the steering policy.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     * 
     */
    @Export(name="healthCheckMonitorId", type=String.class, parameters={})
    private Output<String> healthCheckMonitorId;

    /**
     * @return (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     * 
     */
    public Output<String> healthCheckMonitorId() {
        return this.healthCheckMonitorId;
    }
    /**
     * The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     * 
     */
    @Export(name="rules", type=List.class, parameters={SteeringPolicyRule.class})
    private Output<List<SteeringPolicyRule>> rules;

    /**
     * @return The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     * 
     */
    public Output<List<SteeringPolicyRule>> rules() {
        return this.rules;
    }
    /**
     * The canonical absolute URL of the resource.
     * 
     */
    @Export(name="self", type=String.class, parameters={})
    private Output<String> self;

    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    public Output<String> self() {
        return this.self;
    }
    /**
     * The current state of the resource.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management&#39;s rules in a different order to produce the desired results when answering DNS queries.
     * 
     */
    @Export(name="template", type=String.class, parameters={})
    private Output<String> template;

    /**
     * @return (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management&#39;s rules in a different order to produce the desired results when answering DNS queries.
     * 
     */
    public Output<String> template() {
        return this.template;
    }
    /**
     * The date and time the resource was created, expressed in RFC 3339 timestamp format.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, expressed in RFC 3339 timestamp format.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used.
     * 
     */
    @Export(name="ttl", type=Integer.class, parameters={})
    private Output<Integer> ttl;

    /**
     * @return (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used.
     * 
     */
    public Output<Integer> ttl() {
        return this.ttl;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SteeringPolicy(String name) {
        this(name, SteeringPolicyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SteeringPolicy(String name, SteeringPolicyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SteeringPolicy(String name, SteeringPolicyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/steeringPolicy:SteeringPolicy", name, args == null ? SteeringPolicyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private SteeringPolicy(String name, Output<String> id, @Nullable SteeringPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/steeringPolicy:SteeringPolicy", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static SteeringPolicy get(String name, Output<String> id, @Nullable SteeringPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SteeringPolicy(name, id, state, options);
    }
}
