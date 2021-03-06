// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.GetRuleSetsFilter;
import com.pulumi.oci.LoadBalancer.outputs.GetRuleSetsRuleSet;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetRuleSetsResult {
    private final @Nullable List<GetRuleSetsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String loadBalancerId;
    /**
     * @return The list of rule_sets.
     * 
     */
    private final List<GetRuleSetsRuleSet> ruleSets;

    @CustomType.Constructor
    private GetRuleSetsResult(
        @CustomType.Parameter("filters") @Nullable List<GetRuleSetsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("loadBalancerId") String loadBalancerId,
        @CustomType.Parameter("ruleSets") List<GetRuleSetsRuleSet> ruleSets) {
        this.filters = filters;
        this.id = id;
        this.loadBalancerId = loadBalancerId;
        this.ruleSets = ruleSets;
    }

    public List<GetRuleSetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * @return The list of rule_sets.
     * 
     */
    public List<GetRuleSetsRuleSet> ruleSets() {
        return this.ruleSets;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRuleSetsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<GetRuleSetsFilter> filters;
        private String id;
        private String loadBalancerId;
        private List<GetRuleSetsRuleSet> ruleSets;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRuleSetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.ruleSets = defaults.ruleSets;
        }

        public Builder filters(@Nullable List<GetRuleSetsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetRuleSetsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder loadBalancerId(String loadBalancerId) {
            this.loadBalancerId = Objects.requireNonNull(loadBalancerId);
            return this;
        }
        public Builder ruleSets(List<GetRuleSetsRuleSet> ruleSets) {
            this.ruleSets = Objects.requireNonNull(ruleSets);
            return this;
        }
        public Builder ruleSets(GetRuleSetsRuleSet... ruleSets) {
            return ruleSets(List.of(ruleSets));
        }        public GetRuleSetsResult build() {
            return new GetRuleSetsResult(filters, id, loadBalancerId, ruleSets);
        }
    }
}
