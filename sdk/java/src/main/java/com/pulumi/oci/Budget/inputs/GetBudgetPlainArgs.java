// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Budget.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBudgetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBudgetPlainArgs Empty = new GetBudgetPlainArgs();

    /**
     * The unique budget OCID.
     * 
     */
    @Import(name="budgetId", required=true)
    private String budgetId;

    /**
     * @return The unique budget OCID.
     * 
     */
    public String budgetId() {
        return this.budgetId;
    }

    private GetBudgetPlainArgs() {}

    private GetBudgetPlainArgs(GetBudgetPlainArgs $) {
        this.budgetId = $.budgetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBudgetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBudgetPlainArgs $;

        public Builder() {
            $ = new GetBudgetPlainArgs();
        }

        public Builder(GetBudgetPlainArgs defaults) {
            $ = new GetBudgetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param budgetId The unique budget OCID.
         * 
         * @return builder
         * 
         */
        public Builder budgetId(String budgetId) {
            $.budgetId = budgetId;
            return this;
        }

        public GetBudgetPlainArgs build() {
            if ($.budgetId == null) {
                throw new MissingRequiredPropertyException("GetBudgetPlainArgs", "budgetId");
            }
            return $;
        }
    }

}
