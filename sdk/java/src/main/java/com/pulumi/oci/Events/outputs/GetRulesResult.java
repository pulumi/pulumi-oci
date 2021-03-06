// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Events.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Events.outputs.GetRulesFilter;
import com.pulumi.oci.Events.outputs.GetRulesRule;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRulesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     * 
     */
    private final String compartmentId;
    /**
     * @return A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `&#34;This rule sends a notification upon completion of DbaaS backup.&#34;`
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetRulesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of rules.
     * 
     */
    private final List<GetRulesRule> rules;
    /**
     * @return The current state of the rule.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetRulesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetRulesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("rules") List<GetRulesRule> rules,
        @CustomType.Parameter("state") @Nullable String state) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.rules = rules;
        this.state = state;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `&#34;This rule sends a notification upon completion of DbaaS backup.&#34;`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetRulesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of rules.
     * 
     */
    public List<GetRulesRule> rules() {
        return this.rules;
    }
    /**
     * @return The current state of the rule.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRulesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetRulesFilter> filters;
        private String id;
        private List<GetRulesRule> rules;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRulesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.rules = defaults.rules;
    	      this.state = defaults.state;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetRulesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetRulesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder rules(List<GetRulesRule> rules) {
            this.rules = Objects.requireNonNull(rules);
            return this;
        }
        public Builder rules(GetRulesRule... rules) {
            return rules(List.of(rules));
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetRulesResult build() {
            return new GetRulesResult(compartmentId, displayName, filters, id, rules, state);
        }
    }
}
