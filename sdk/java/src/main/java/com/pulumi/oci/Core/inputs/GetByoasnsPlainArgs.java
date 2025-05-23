// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.GetByoasnsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetByoasnsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetByoasnsPlainArgs Empty = new GetByoasnsPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetByoasnsFilter> filters;

    public Optional<List<GetByoasnsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetByoasnsPlainArgs() {}

    private GetByoasnsPlainArgs(GetByoasnsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetByoasnsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetByoasnsPlainArgs $;

        public Builder() {
            $ = new GetByoasnsPlainArgs();
        }

        public Builder(GetByoasnsPlainArgs defaults) {
            $ = new GetByoasnsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetByoasnsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetByoasnsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetByoasnsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetByoasnsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
