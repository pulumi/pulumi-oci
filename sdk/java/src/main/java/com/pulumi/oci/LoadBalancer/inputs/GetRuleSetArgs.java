// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetRuleSetArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRuleSetArgs Empty = new GetRuleSetArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }

    /**
     * The name of the rule set to retrieve.  Example: `example_rule_set`
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return The name of the rule set to retrieve.  Example: `example_rule_set`
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    private GetRuleSetArgs() {}

    private GetRuleSetArgs(GetRuleSetArgs $) {
        this.loadBalancerId = $.loadBalancerId;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRuleSetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRuleSetArgs $;

        public Builder() {
            $ = new GetRuleSetArgs();
        }

        public Builder(GetRuleSetArgs defaults) {
            $ = new GetRuleSetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        /**
         * @param name The name of the rule set to retrieve.  Example: `example_rule_set`
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the rule set to retrieve.  Example: `example_rule_set`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetRuleSetArgs build() {
            $.loadBalancerId = Objects.requireNonNull($.loadBalancerId, "expected parameter 'loadBalancerId' to be non-null");
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}