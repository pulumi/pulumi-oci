// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OneSubsription.inputs.GetCommitmentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCommitmentsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCommitmentsPlainArgs Empty = new GetCommitmentsPlainArgs();

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
    private @Nullable List<GetCommitmentsFilter> filters;

    public Optional<List<GetCommitmentsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * This param is used to get the commitments for a particular subscribed service
     * 
     */
    @Import(name="subscribedServiceId", required=true)
    private String subscribedServiceId;

    /**
     * @return This param is used to get the commitments for a particular subscribed service
     * 
     */
    public String subscribedServiceId() {
        return this.subscribedServiceId;
    }

    private GetCommitmentsPlainArgs() {}

    private GetCommitmentsPlainArgs(GetCommitmentsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.subscribedServiceId = $.subscribedServiceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCommitmentsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCommitmentsPlainArgs $;

        public Builder() {
            $ = new GetCommitmentsPlainArgs();
        }

        public Builder(GetCommitmentsPlainArgs defaults) {
            $ = new GetCommitmentsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetCommitmentsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetCommitmentsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param subscribedServiceId This param is used to get the commitments for a particular subscribed service
         * 
         * @return builder
         * 
         */
        public Builder subscribedServiceId(String subscribedServiceId) {
            $.subscribedServiceId = subscribedServiceId;
            return this;
        }

        public GetCommitmentsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.subscribedServiceId = Objects.requireNonNull($.subscribedServiceId, "expected parameter 'subscribedServiceId' to be non-null");
            return $;
        }
    }

}