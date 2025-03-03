// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.UsageProxy.inputs.GetUsagelimitsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetUsagelimitsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUsagelimitsArgs Empty = new GetUsagelimitsArgs();

    /**
     * The OCID of the root compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the root compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetUsagelimitsFilterArgs>> filters;

    public Optional<Output<List<GetUsagelimitsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Hard or soft limit. Hard limits lead to breaches, soft to alerts.
     * 
     */
    @Import(name="limitType")
    private @Nullable Output<String> limitType;

    /**
     * @return Hard or soft limit. Hard limits lead to breaches, soft to alerts.
     * 
     */
    public Optional<Output<String>> limitType() {
        return Optional.ofNullable(this.limitType);
    }

    /**
     * Resource Name.
     * 
     */
    @Import(name="resourceType")
    private @Nullable Output<String> resourceType;

    /**
     * @return Resource Name.
     * 
     */
    public Optional<Output<String>> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    /**
     * Service Name.
     * 
     */
    @Import(name="serviceType")
    private @Nullable Output<String> serviceType;

    /**
     * @return Service Name.
     * 
     */
    public Optional<Output<String>> serviceType() {
        return Optional.ofNullable(this.serviceType);
    }

    /**
     * The subscription ID for which rewards information is requested for.
     * 
     */
    @Import(name="subscriptionId", required=true)
    private Output<String> subscriptionId;

    /**
     * @return The subscription ID for which rewards information is requested for.
     * 
     */
    public Output<String> subscriptionId() {
        return this.subscriptionId;
    }

    private GetUsagelimitsArgs() {}

    private GetUsagelimitsArgs(GetUsagelimitsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.limitType = $.limitType;
        this.resourceType = $.resourceType;
        this.serviceType = $.serviceType;
        this.subscriptionId = $.subscriptionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUsagelimitsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUsagelimitsArgs $;

        public Builder() {
            $ = new GetUsagelimitsArgs();
        }

        public Builder(GetUsagelimitsArgs defaults) {
            $ = new GetUsagelimitsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetUsagelimitsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetUsagelimitsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetUsagelimitsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param limitType Hard or soft limit. Hard limits lead to breaches, soft to alerts.
         * 
         * @return builder
         * 
         */
        public Builder limitType(@Nullable Output<String> limitType) {
            $.limitType = limitType;
            return this;
        }

        /**
         * @param limitType Hard or soft limit. Hard limits lead to breaches, soft to alerts.
         * 
         * @return builder
         * 
         */
        public Builder limitType(String limitType) {
            return limitType(Output.of(limitType));
        }

        /**
         * @param resourceType Resource Name.
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable Output<String> resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param resourceType Resource Name.
         * 
         * @return builder
         * 
         */
        public Builder resourceType(String resourceType) {
            return resourceType(Output.of(resourceType));
        }

        /**
         * @param serviceType Service Name.
         * 
         * @return builder
         * 
         */
        public Builder serviceType(@Nullable Output<String> serviceType) {
            $.serviceType = serviceType;
            return this;
        }

        /**
         * @param serviceType Service Name.
         * 
         * @return builder
         * 
         */
        public Builder serviceType(String serviceType) {
            return serviceType(Output.of(serviceType));
        }

        /**
         * @param subscriptionId The subscription ID for which rewards information is requested for.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(Output<String> subscriptionId) {
            $.subscriptionId = subscriptionId;
            return this;
        }

        /**
         * @param subscriptionId The subscription ID for which rewards information is requested for.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(String subscriptionId) {
            return subscriptionId(Output.of(subscriptionId));
        }

        public GetUsagelimitsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetUsagelimitsArgs", "compartmentId");
            }
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetUsagelimitsArgs", "subscriptionId");
            }
            return $;
        }
    }

}
