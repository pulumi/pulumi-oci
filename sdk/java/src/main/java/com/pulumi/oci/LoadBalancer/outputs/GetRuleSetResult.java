// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.GetRuleSetItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRuleSetResult {
    private String id;
    /**
     * @return An array of rules that compose the rule set.
     * 
     */
    private List<GetRuleSetItem> items;
    private String loadBalancerId;
    /**
     * @return The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_rule_set`
     * 
     */
    private String name;
    private String state;

    private GetRuleSetResult() {}
    public String id() {
        return this.id;
    }
    /**
     * @return An array of rules that compose the rule set.
     * 
     */
    public List<GetRuleSetItem> items() {
        return this.items;
    }
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * @return The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_rule_set`
     * 
     */
    public String name() {
        return this.name;
    }
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRuleSetResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private List<GetRuleSetItem> items;
        private String loadBalancerId;
        private String name;
        private String state;
        public Builder() {}
        public Builder(GetRuleSetResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetRuleSetItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetRuleSetItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder loadBalancerId(String loadBalancerId) {
            this.loadBalancerId = Objects.requireNonNull(loadBalancerId);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public GetRuleSetResult build() {
            final var o = new GetRuleSetResult();
            o.id = id;
            o.items = items;
            o.loadBalancerId = loadBalancerId;
            o.name = name;
            o.state = state;
            return o;
        }
    }
}