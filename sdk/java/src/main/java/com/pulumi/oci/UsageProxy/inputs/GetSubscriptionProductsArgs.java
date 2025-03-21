// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.UsageProxy.inputs.GetSubscriptionProductsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSubscriptionProductsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSubscriptionProductsArgs Empty = new GetSubscriptionProductsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetSubscriptionProductsFilterArgs>> filters;

    public Optional<Output<List<GetSubscriptionProductsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The field to specify the type of product.
     * 
     */
    @Import(name="producttype")
    private @Nullable Output<String> producttype;

    /**
     * @return The field to specify the type of product.
     * 
     */
    public Optional<Output<String>> producttype() {
        return Optional.ofNullable(this.producttype);
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

    /**
     * The OCID of the tenancy.
     * 
     */
    @Import(name="tenancyId", required=true)
    private Output<String> tenancyId;

    /**
     * @return The OCID of the tenancy.
     * 
     */
    public Output<String> tenancyId() {
        return this.tenancyId;
    }

    /**
     * The SPM Identifier for the usage period.
     * 
     */
    @Import(name="usagePeriodKey", required=true)
    private Output<String> usagePeriodKey;

    /**
     * @return The SPM Identifier for the usage period.
     * 
     */
    public Output<String> usagePeriodKey() {
        return this.usagePeriodKey;
    }

    private GetSubscriptionProductsArgs() {}

    private GetSubscriptionProductsArgs(GetSubscriptionProductsArgs $) {
        this.filters = $.filters;
        this.producttype = $.producttype;
        this.subscriptionId = $.subscriptionId;
        this.tenancyId = $.tenancyId;
        this.usagePeriodKey = $.usagePeriodKey;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSubscriptionProductsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSubscriptionProductsArgs $;

        public Builder() {
            $ = new GetSubscriptionProductsArgs();
        }

        public Builder(GetSubscriptionProductsArgs defaults) {
            $ = new GetSubscriptionProductsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetSubscriptionProductsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSubscriptionProductsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSubscriptionProductsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param producttype The field to specify the type of product.
         * 
         * @return builder
         * 
         */
        public Builder producttype(@Nullable Output<String> producttype) {
            $.producttype = producttype;
            return this;
        }

        /**
         * @param producttype The field to specify the type of product.
         * 
         * @return builder
         * 
         */
        public Builder producttype(String producttype) {
            return producttype(Output.of(producttype));
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

        /**
         * @param tenancyId The OCID of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(Output<String> tenancyId) {
            $.tenancyId = tenancyId;
            return this;
        }

        /**
         * @param tenancyId The OCID of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(String tenancyId) {
            return tenancyId(Output.of(tenancyId));
        }

        /**
         * @param usagePeriodKey The SPM Identifier for the usage period.
         * 
         * @return builder
         * 
         */
        public Builder usagePeriodKey(Output<String> usagePeriodKey) {
            $.usagePeriodKey = usagePeriodKey;
            return this;
        }

        /**
         * @param usagePeriodKey The SPM Identifier for the usage period.
         * 
         * @return builder
         * 
         */
        public Builder usagePeriodKey(String usagePeriodKey) {
            return usagePeriodKey(Output.of(usagePeriodKey));
        }

        public GetSubscriptionProductsArgs build() {
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionProductsArgs", "subscriptionId");
            }
            if ($.tenancyId == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionProductsArgs", "tenancyId");
            }
            if ($.usagePeriodKey == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionProductsArgs", "usagePeriodKey");
            }
            return $;
        }
    }

}
