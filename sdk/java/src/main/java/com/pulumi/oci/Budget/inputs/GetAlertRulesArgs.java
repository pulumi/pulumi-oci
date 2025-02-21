// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Budget.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Budget.inputs.GetAlertRulesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAlertRulesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAlertRulesArgs Empty = new GetAlertRulesArgs();

    /**
     * The unique budget OCID.
     * 
     */
    @Import(name="budgetId", required=true)
    private Output<String> budgetId;

    /**
     * @return The unique budget OCID.
     * 
     */
    public Output<String> budgetId() {
        return this.budgetId;
    }

    /**
     * A user-friendly name. This does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. This does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAlertRulesFilterArgs>> filters;

    public Optional<Output<List<GetAlertRulesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The current state of the resource to filter by.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the resource to filter by.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetAlertRulesArgs() {}

    private GetAlertRulesArgs(GetAlertRulesArgs $) {
        this.budgetId = $.budgetId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAlertRulesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAlertRulesArgs $;

        public Builder() {
            $ = new GetAlertRulesArgs();
        }

        public Builder(GetAlertRulesArgs defaults) {
            $ = new GetAlertRulesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param budgetId The unique budget OCID.
         * 
         * @return builder
         * 
         */
        public Builder budgetId(Output<String> budgetId) {
            $.budgetId = budgetId;
            return this;
        }

        /**
         * @param budgetId The unique budget OCID.
         * 
         * @return builder
         * 
         */
        public Builder budgetId(String budgetId) {
            return budgetId(Output.of(budgetId));
        }

        /**
         * @param displayName A user-friendly name. This does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. This does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAlertRulesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAlertRulesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAlertRulesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state The current state of the resource to filter by.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the resource to filter by.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetAlertRulesArgs build() {
            if ($.budgetId == null) {
                throw new MissingRequiredPropertyException("GetAlertRulesArgs", "budgetId");
            }
            return $;
        }
    }

}
