// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Budget.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Budget.outputs.GetBudgetsBudget;
import com.pulumi.oci.Budget.outputs.GetBudgetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBudgetsResult {
    /**
     * @return The list of budgets.
     * 
     */
    private final List<GetBudgetsBudget> budgets;
    /**
     * @return The OCID of the compartment
     * 
     */
    private final String compartmentId;
    /**
     * @return The display name of the budget.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetBudgetsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The current state of the budget.
     * 
     */
    private final @Nullable String state;
    /**
     * @return The type of target on which the budget is applied.
     * 
     */
    private final @Nullable String targetType;

    @CustomType.Constructor
    private GetBudgetsResult(
        @CustomType.Parameter("budgets") List<GetBudgetsBudget> budgets,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetBudgetsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("targetType") @Nullable String targetType) {
        this.budgets = budgets;
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.state = state;
        this.targetType = targetType;
    }

    /**
     * @return The list of budgets.
     * 
     */
    public List<GetBudgetsBudget> budgets() {
        return this.budgets;
    }
    /**
     * @return The OCID of the compartment
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The display name of the budget.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetBudgetsFilter> filters() {
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
     * @return The current state of the budget.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The type of target on which the budget is applied.
     * 
     */
    public Optional<String> targetType() {
        return Optional.ofNullable(this.targetType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBudgetsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBudgetsBudget> budgets;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetBudgetsFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String targetType;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBudgetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.budgets = defaults.budgets;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.targetType = defaults.targetType;
        }

        public Builder budgets(List<GetBudgetsBudget> budgets) {
            this.budgets = Objects.requireNonNull(budgets);
            return this;
        }
        public Builder budgets(GetBudgetsBudget... budgets) {
            return budgets(List.of(budgets));
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetBudgetsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBudgetsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder targetType(@Nullable String targetType) {
            this.targetType = targetType;
            return this;
        }        public GetBudgetsResult build() {
            return new GetBudgetsResult(budgets, compartmentId, displayName, filters, id, state, targetType);
        }
    }
}
