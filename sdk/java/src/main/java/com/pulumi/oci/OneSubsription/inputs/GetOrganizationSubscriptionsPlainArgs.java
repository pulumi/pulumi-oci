// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OneSubsription.inputs.GetOrganizationSubscriptionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOrganizationSubscriptionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOrganizationSubscriptionsPlainArgs Empty = new GetOrganizationSubscriptionsPlainArgs();

    /**
     * The OCID of the root compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the root compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetOrganizationSubscriptionsFilter> filters;

    public Optional<List<GetOrganizationSubscriptionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetOrganizationSubscriptionsPlainArgs() {}

    private GetOrganizationSubscriptionsPlainArgs(GetOrganizationSubscriptionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOrganizationSubscriptionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOrganizationSubscriptionsPlainArgs $;

        public Builder() {
            $ = new GetOrganizationSubscriptionsPlainArgs();
        }

        public Builder(GetOrganizationSubscriptionsPlainArgs defaults) {
            $ = new GetOrganizationSubscriptionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetOrganizationSubscriptionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetOrganizationSubscriptionsFilter... filters) {
            return filters(List.of(filters));
        }

        public GetOrganizationSubscriptionsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetOrganizationSubscriptionsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
