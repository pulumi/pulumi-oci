// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Events.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Events.outputs.GetRulesRuleActionAction;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRulesRuleAction {
    /**
     * @return A list of one or more Action objects.
     * 
     */
    private List<GetRulesRuleActionAction> actions;

    private GetRulesRuleAction() {}
    /**
     * @return A list of one or more Action objects.
     * 
     */
    public List<GetRulesRuleActionAction> actions() {
        return this.actions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRulesRuleAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetRulesRuleActionAction> actions;
        public Builder() {}
        public Builder(GetRulesRuleAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
        }

        @CustomType.Setter
        public Builder actions(List<GetRulesRuleActionAction> actions) {
            this.actions = Objects.requireNonNull(actions);
            return this;
        }
        public Builder actions(GetRulesRuleActionAction... actions) {
            return actions(List.of(actions));
        }
        public GetRulesRuleAction build() {
            final var o = new GetRulesRuleAction();
            o.actions = actions;
            return o;
        }
    }
}