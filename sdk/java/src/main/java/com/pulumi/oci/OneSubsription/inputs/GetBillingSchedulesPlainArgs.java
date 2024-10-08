// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OneSubsription.inputs.GetBillingSchedulesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBillingSchedulesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBillingSchedulesPlainArgs Empty = new GetBillingSchedulesPlainArgs();

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
    private @Nullable List<GetBillingSchedulesFilter> filters;

    public Optional<List<GetBillingSchedulesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * This param is used to get only the billing schedules for a particular Subscribed Service
     * 
     */
    @Import(name="subscribedServiceId")
    private @Nullable String subscribedServiceId;

    /**
     * @return This param is used to get only the billing schedules for a particular Subscribed Service
     * 
     */
    public Optional<String> subscribedServiceId() {
        return Optional.ofNullable(this.subscribedServiceId);
    }

    /**
     * This param is used to get only the billing schedules for a particular Subscription Id
     * 
     */
    @Import(name="subscriptionId", required=true)
    private String subscriptionId;

    /**
     * @return This param is used to get only the billing schedules for a particular Subscription Id
     * 
     */
    public String subscriptionId() {
        return this.subscriptionId;
    }

    private GetBillingSchedulesPlainArgs() {}

    private GetBillingSchedulesPlainArgs(GetBillingSchedulesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.subscribedServiceId = $.subscribedServiceId;
        this.subscriptionId = $.subscriptionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBillingSchedulesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBillingSchedulesPlainArgs $;

        public Builder() {
            $ = new GetBillingSchedulesPlainArgs();
        }

        public Builder(GetBillingSchedulesPlainArgs defaults) {
            $ = new GetBillingSchedulesPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetBillingSchedulesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetBillingSchedulesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param subscribedServiceId This param is used to get only the billing schedules for a particular Subscribed Service
         * 
         * @return builder
         * 
         */
        public Builder subscribedServiceId(@Nullable String subscribedServiceId) {
            $.subscribedServiceId = subscribedServiceId;
            return this;
        }

        /**
         * @param subscriptionId This param is used to get only the billing schedules for a particular Subscription Id
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(String subscriptionId) {
            $.subscriptionId = subscriptionId;
            return this;
        }

        public GetBillingSchedulesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetBillingSchedulesPlainArgs", "compartmentId");
            }
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetBillingSchedulesPlainArgs", "subscriptionId");
            }
            return $;
        }
    }

}
