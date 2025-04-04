// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.UsageProxy.inputs.GetUsagelimitsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetUsagelimitsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUsagelimitsPlainArgs Empty = new GetUsagelimitsPlainArgs();

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
    private @Nullable List<GetUsagelimitsFilter> filters;

    public Optional<List<GetUsagelimitsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Hard or soft limit. Hard limits lead to breaches, soft to alerts.
     * 
     */
    @Import(name="limitType")
    private @Nullable String limitType;

    /**
     * @return Hard or soft limit. Hard limits lead to breaches, soft to alerts.
     * 
     */
    public Optional<String> limitType() {
        return Optional.ofNullable(this.limitType);
    }

    /**
     * Resource Name.
     * 
     */
    @Import(name="resourceType")
    private @Nullable String resourceType;

    /**
     * @return Resource Name.
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    /**
     * Service Name.
     * 
     */
    @Import(name="serviceType")
    private @Nullable String serviceType;

    /**
     * @return Service Name.
     * 
     */
    public Optional<String> serviceType() {
        return Optional.ofNullable(this.serviceType);
    }

    /**
     * The subscription ID for which rewards information is requested for.
     * 
     */
    @Import(name="subscriptionId", required=true)
    private String subscriptionId;

    /**
     * @return The subscription ID for which rewards information is requested for.
     * 
     */
    public String subscriptionId() {
        return this.subscriptionId;
    }

    private GetUsagelimitsPlainArgs() {}

    private GetUsagelimitsPlainArgs(GetUsagelimitsPlainArgs $) {
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
    public static Builder builder(GetUsagelimitsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUsagelimitsPlainArgs $;

        public Builder() {
            $ = new GetUsagelimitsPlainArgs();
        }

        public Builder(GetUsagelimitsPlainArgs defaults) {
            $ = new GetUsagelimitsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetUsagelimitsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetUsagelimitsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param limitType Hard or soft limit. Hard limits lead to breaches, soft to alerts.
         * 
         * @return builder
         * 
         */
        public Builder limitType(@Nullable String limitType) {
            $.limitType = limitType;
            return this;
        }

        /**
         * @param resourceType Resource Name.
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable String resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param serviceType Service Name.
         * 
         * @return builder
         * 
         */
        public Builder serviceType(@Nullable String serviceType) {
            $.serviceType = serviceType;
            return this;
        }

        /**
         * @param subscriptionId The subscription ID for which rewards information is requested for.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(String subscriptionId) {
            $.subscriptionId = subscriptionId;
            return this;
        }

        public GetUsagelimitsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetUsagelimitsPlainArgs", "compartmentId");
            }
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetUsagelimitsPlainArgs", "subscriptionId");
            }
            return $;
        }
    }

}
