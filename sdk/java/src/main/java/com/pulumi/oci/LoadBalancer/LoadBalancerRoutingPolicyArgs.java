// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LoadBalancer.inputs.LoadBalancerRoutingPolicyRuleArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class LoadBalancerRoutingPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final LoadBalancerRoutingPolicyArgs Empty = new LoadBalancerRoutingPolicyArgs();

    /**
     * (Updatable) The version of the language in which `condition` of `rules` are composed.
     * 
     */
    @Import(name="conditionLanguageVersion", required=true)
    private Output<String> conditionLanguageVersion;

    /**
     * @return (Updatable) The version of the language in which `condition` of `rules` are composed.
     * 
     */
    public Output<String> conditionLanguageVersion() {
        return this.conditionLanguageVersion;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }

    /**
     * (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The list of routing rules.
     * 
     */
    @Import(name="rules", required=true)
    private Output<List<LoadBalancerRoutingPolicyRuleArgs>> rules;

    /**
     * @return (Updatable) The list of routing rules.
     * 
     */
    public Output<List<LoadBalancerRoutingPolicyRuleArgs>> rules() {
        return this.rules;
    }

    private LoadBalancerRoutingPolicyArgs() {}

    private LoadBalancerRoutingPolicyArgs(LoadBalancerRoutingPolicyArgs $) {
        this.conditionLanguageVersion = $.conditionLanguageVersion;
        this.loadBalancerId = $.loadBalancerId;
        this.name = $.name;
        this.rules = $.rules;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LoadBalancerRoutingPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LoadBalancerRoutingPolicyArgs $;

        public Builder() {
            $ = new LoadBalancerRoutingPolicyArgs();
        }

        public Builder(LoadBalancerRoutingPolicyArgs defaults) {
            $ = new LoadBalancerRoutingPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param conditionLanguageVersion (Updatable) The version of the language in which `condition` of `rules` are composed.
         * 
         * @return builder
         * 
         */
        public Builder conditionLanguageVersion(Output<String> conditionLanguageVersion) {
            $.conditionLanguageVersion = conditionLanguageVersion;
            return this;
        }

        /**
         * @param conditionLanguageVersion (Updatable) The version of the language in which `condition` of `rules` are composed.
         * 
         * @return builder
         * 
         */
        public Builder conditionLanguageVersion(String conditionLanguageVersion) {
            return conditionLanguageVersion(Output.of(conditionLanguageVersion));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        /**
         * @param name (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param rules (Updatable) The list of routing rules.
         * 
         * @return builder
         * 
         */
        public Builder rules(Output<List<LoadBalancerRoutingPolicyRuleArgs>> rules) {
            $.rules = rules;
            return this;
        }

        /**
         * @param rules (Updatable) The list of routing rules.
         * 
         * @return builder
         * 
         */
        public Builder rules(List<LoadBalancerRoutingPolicyRuleArgs> rules) {
            return rules(Output.of(rules));
        }

        /**
         * @param rules (Updatable) The list of routing rules.
         * 
         * @return builder
         * 
         */
        public Builder rules(LoadBalancerRoutingPolicyRuleArgs... rules) {
            return rules(List.of(rules));
        }

        public LoadBalancerRoutingPolicyArgs build() {
            $.conditionLanguageVersion = Objects.requireNonNull($.conditionLanguageVersion, "expected parameter 'conditionLanguageVersion' to be non-null");
            $.loadBalancerId = Objects.requireNonNull($.loadBalancerId, "expected parameter 'loadBalancerId' to be non-null");
            $.rules = Objects.requireNonNull($.rules, "expected parameter 'rules' to be non-null");
            return $;
        }
    }

}