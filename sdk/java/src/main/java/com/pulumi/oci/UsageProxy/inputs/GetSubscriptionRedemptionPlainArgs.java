// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSubscriptionRedemptionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSubscriptionRedemptionPlainArgs Empty = new GetSubscriptionRedemptionPlainArgs();

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

    /**
     * The OCID of the tenancy.
     * 
     */
    @Import(name="tenancyId", required=true)
    private String tenancyId;

    /**
     * @return The OCID of the tenancy.
     * 
     */
    public String tenancyId() {
        return this.tenancyId;
    }

    /**
     * The starting redeemed date filter for the redemption history.
     * 
     */
    @Import(name="timeRedeemedGreaterThanOrEqualTo")
    private @Nullable String timeRedeemedGreaterThanOrEqualTo;

    /**
     * @return The starting redeemed date filter for the redemption history.
     * 
     */
    public Optional<String> timeRedeemedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeRedeemedGreaterThanOrEqualTo);
    }

    /**
     * The ending redeemed date filter for the redemption history.
     * 
     */
    @Import(name="timeRedeemedLessThan")
    private @Nullable String timeRedeemedLessThan;

    /**
     * @return The ending redeemed date filter for the redemption history.
     * 
     */
    public Optional<String> timeRedeemedLessThan() {
        return Optional.ofNullable(this.timeRedeemedLessThan);
    }

    private GetSubscriptionRedemptionPlainArgs() {}

    private GetSubscriptionRedemptionPlainArgs(GetSubscriptionRedemptionPlainArgs $) {
        this.subscriptionId = $.subscriptionId;
        this.tenancyId = $.tenancyId;
        this.timeRedeemedGreaterThanOrEqualTo = $.timeRedeemedGreaterThanOrEqualTo;
        this.timeRedeemedLessThan = $.timeRedeemedLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSubscriptionRedemptionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSubscriptionRedemptionPlainArgs $;

        public Builder() {
            $ = new GetSubscriptionRedemptionPlainArgs();
        }

        public Builder(GetSubscriptionRedemptionPlainArgs defaults) {
            $ = new GetSubscriptionRedemptionPlainArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param tenancyId The OCID of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(String tenancyId) {
            $.tenancyId = tenancyId;
            return this;
        }

        /**
         * @param timeRedeemedGreaterThanOrEqualTo The starting redeemed date filter for the redemption history.
         * 
         * @return builder
         * 
         */
        public Builder timeRedeemedGreaterThanOrEqualTo(@Nullable String timeRedeemedGreaterThanOrEqualTo) {
            $.timeRedeemedGreaterThanOrEqualTo = timeRedeemedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeRedeemedLessThan The ending redeemed date filter for the redemption history.
         * 
         * @return builder
         * 
         */
        public Builder timeRedeemedLessThan(@Nullable String timeRedeemedLessThan) {
            $.timeRedeemedLessThan = timeRedeemedLessThan;
            return this;
        }

        public GetSubscriptionRedemptionPlainArgs build() {
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionRedemptionPlainArgs", "subscriptionId");
            }
            if ($.tenancyId == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionRedemptionPlainArgs", "tenancyId");
            }
            return $;
        }
    }

}
