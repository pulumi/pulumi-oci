// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Dns.inputs.SteeringPolicyAnswerArgs;
import com.pulumi.oci.Dns.inputs.SteeringPolicyRuleArgs;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SteeringPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final SteeringPolicyArgs Empty = new SteeringPolicyArgs();

    /**
     * The set of all answers that can potentially issue from the steering policy.
     * 
     */
    @Import(name="answers")
    private @Nullable Output<List<SteeringPolicyAnswerArgs>> answers;

    /**
     * @return The set of all answers that can potentially issue from the steering policy.
     * 
     */
    public Optional<Output<List<SteeringPolicyAnswerArgs>>> answers() {
        return Optional.ofNullable(this.answers);
    }

    /**
     * (Updatable) The OCID of the compartment containing the steering policy.
     * 
     */
    @Import(name="compartmentId", required=true)
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
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
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
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     * 
     */
    @Import(name="healthCheckMonitorId")
    private @Nullable Output<String> healthCheckMonitorId;

    /**
     * @return (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
     * 
     */
    public Optional<Output<String>> healthCheckMonitorId() {
        return Optional.ofNullable(this.healthCheckMonitorId);
    }

    /**
     * The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     * 
     */
    @Import(name="rules")
    private @Nullable Output<List<SteeringPolicyRuleArgs>> rules;

    /**
     * @return The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
     * 
     */
    public Optional<Output<List<SteeringPolicyRuleArgs>>> rules() {
        return Optional.ofNullable(this.rules);
    }

    /**
     * (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management&#39;s rules in a different order to produce the desired results when answering DNS queries.
     * 
     */
    @Import(name="template", required=true)
    private Output<String> template;

    /**
     * @return (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management&#39;s rules in a different order to produce the desired results when answering DNS queries.
     * 
     */
    public Output<String> template() {
        return this.template;
    }

    /**
     * (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used.
     * 
     */
    @Import(name="ttl")
    private @Nullable Output<Integer> ttl;

    /**
     * @return (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used.
     * 
     */
    public Optional<Output<Integer>> ttl() {
        return Optional.ofNullable(this.ttl);
    }

    private SteeringPolicyArgs() {}

    private SteeringPolicyArgs(SteeringPolicyArgs $) {
        this.answers = $.answers;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.healthCheckMonitorId = $.healthCheckMonitorId;
        this.rules = $.rules;
        this.template = $.template;
        this.ttl = $.ttl;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SteeringPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SteeringPolicyArgs $;

        public Builder() {
            $ = new SteeringPolicyArgs();
        }

        public Builder(SteeringPolicyArgs defaults) {
            $ = new SteeringPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param answers The set of all answers that can potentially issue from the steering policy.
         * 
         * @return builder
         * 
         */
        public Builder answers(@Nullable Output<List<SteeringPolicyAnswerArgs>> answers) {
            $.answers = answers;
            return this;
        }

        /**
         * @param answers The set of all answers that can potentially issue from the steering policy.
         * 
         * @return builder
         * 
         */
        public Builder answers(List<SteeringPolicyAnswerArgs> answers) {
            return answers(Output.of(answers));
        }

        /**
         * @param answers The set of all answers that can potentially issue from the steering policy.
         * 
         * @return builder
         * 
         */
        public Builder answers(SteeringPolicyAnswerArgs... answers) {
            return answers(List.of(answers));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the steering policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the steering policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the steering policy. Does not have to be unique and can be changed. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param healthCheckMonitorId (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
         * 
         * @return builder
         * 
         */
        public Builder healthCheckMonitorId(@Nullable Output<String> healthCheckMonitorId) {
            $.healthCheckMonitorId = healthCheckMonitorId;
            return this;
        }

        /**
         * @param healthCheckMonitorId (Updatable) The OCID of the health check monitor providing health data about the answers of the steering policy. A steering policy answer with `rdata` matching a monitored endpoint will use the health data of that endpoint. A steering policy answer with `rdata` not matching any monitored endpoint will be assumed healthy.
         * 
         * @return builder
         * 
         */
        public Builder healthCheckMonitorId(String healthCheckMonitorId) {
            return healthCheckMonitorId(Output.of(healthCheckMonitorId));
        }

        /**
         * @param rules The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
         * 
         * @return builder
         * 
         */
        public Builder rules(@Nullable Output<List<SteeringPolicyRuleArgs>> rules) {
            $.rules = rules;
            return this;
        }

        /**
         * @param rules The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
         * 
         * @return builder
         * 
         */
        public Builder rules(List<SteeringPolicyRuleArgs> rules) {
            return rules(Output.of(rules));
        }

        /**
         * @param rules The series of rules that will be processed in sequence to reduce the pool of answers to a response for any given request.
         * 
         * @return builder
         * 
         */
        public Builder rules(SteeringPolicyRuleArgs... rules) {
            return rules(List.of(rules));
        }

        /**
         * @param template (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management&#39;s rules in a different order to produce the desired results when answering DNS queries.
         * 
         * @return builder
         * 
         */
        public Builder template(Output<String> template) {
            $.template = template;
            return this;
        }

        /**
         * @param template (Updatable) A set of predefined rules based on the desired purpose of the steering policy. Each template utilizes Traffic Management&#39;s rules in a different order to produce the desired results when answering DNS queries.
         * 
         * @return builder
         * 
         */
        public Builder template(String template) {
            return template(Output.of(template));
        }

        /**
         * @param ttl (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used.
         * 
         * @return builder
         * 
         */
        public Builder ttl(@Nullable Output<Integer> ttl) {
            $.ttl = ttl;
            return this;
        }

        /**
         * @param ttl (Updatable) The Time To Live (TTL) for responses from the steering policy, in seconds. If not specified during creation, a value of 30 seconds will be used.
         * 
         * @return builder
         * 
         */
        public Builder ttl(Integer ttl) {
            return ttl(Output.of(ttl));
        }

        public SteeringPolicyArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.template = Objects.requireNonNull($.template, "expected parameter 'template' to be non-null");
            return $;
        }
    }

}