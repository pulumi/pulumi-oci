// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LoadBalancer.inputs.LoadBalancerRoutingPolicyRuleActionArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class LoadBalancerRoutingPolicyRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final LoadBalancerRoutingPolicyRuleArgs Empty = new LoadBalancerRoutingPolicyRuleArgs();

    /**
     * (Updatable) A list of actions to be applied when conditions of the routing rule are met.
     * 
     */
    @Import(name="actions", required=true)
    private Output<List<LoadBalancerRoutingPolicyRuleActionArgs>> actions;

    /**
     * @return (Updatable) A list of actions to be applied when conditions of the routing rule are met.
     * 
     */
    public Output<List<LoadBalancerRoutingPolicyRuleActionArgs>> actions() {
        return this.actions;
    }

    /**
     * (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
     * 
     */
    @Import(name="condition", required=true)
    private Output<String> condition;

    /**
     * @return (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
     * 
     */
    public Output<String> condition() {
        return this.condition;
    }

    /**
     * (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    private LoadBalancerRoutingPolicyRuleArgs() {}

    private LoadBalancerRoutingPolicyRuleArgs(LoadBalancerRoutingPolicyRuleArgs $) {
        this.actions = $.actions;
        this.condition = $.condition;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LoadBalancerRoutingPolicyRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LoadBalancerRoutingPolicyRuleArgs $;

        public Builder() {
            $ = new LoadBalancerRoutingPolicyRuleArgs();
        }

        public Builder(LoadBalancerRoutingPolicyRuleArgs defaults) {
            $ = new LoadBalancerRoutingPolicyRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param actions (Updatable) A list of actions to be applied when conditions of the routing rule are met.
         * 
         * @return builder
         * 
         */
        public Builder actions(Output<List<LoadBalancerRoutingPolicyRuleActionArgs>> actions) {
            $.actions = actions;
            return this;
        }

        /**
         * @param actions (Updatable) A list of actions to be applied when conditions of the routing rule are met.
         * 
         * @return builder
         * 
         */
        public Builder actions(List<LoadBalancerRoutingPolicyRuleActionArgs> actions) {
            return actions(Output.of(actions));
        }

        /**
         * @param actions (Updatable) A list of actions to be applied when conditions of the routing rule are met.
         * 
         * @return builder
         * 
         */
        public Builder actions(LoadBalancerRoutingPolicyRuleActionArgs... actions) {
            return actions(List.of(actions));
        }

        /**
         * @param condition (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
         * 
         * @return builder
         * 
         */
        public Builder condition(Output<String> condition) {
            $.condition = condition;
            return this;
        }

        /**
         * @param condition (Updatable) A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
         * 
         * @return builder
         * 
         */
        public Builder condition(String condition) {
            return condition(Output.of(condition));
        }

        /**
         * @param name (Updatable) A unique name for the routing policy rule. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
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

        public LoadBalancerRoutingPolicyRuleArgs build() {
            $.actions = Objects.requireNonNull($.actions, "expected parameter 'actions' to be non-null");
            $.condition = Objects.requireNonNull($.condition, "expected parameter 'condition' to be non-null");
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}