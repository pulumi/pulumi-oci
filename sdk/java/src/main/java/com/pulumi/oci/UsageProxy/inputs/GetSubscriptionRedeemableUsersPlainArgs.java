// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.UsageProxy.inputs.GetSubscriptionRedeemableUsersFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSubscriptionRedeemableUsersPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSubscriptionRedeemableUsersPlainArgs Empty = new GetSubscriptionRedeemableUsersPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetSubscriptionRedeemableUsersFilter> filters;

    public Optional<List<GetSubscriptionRedeemableUsersFilter>> filters() {
        return Optional.ofNullable(this.filters);
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

    private GetSubscriptionRedeemableUsersPlainArgs() {}

    private GetSubscriptionRedeemableUsersPlainArgs(GetSubscriptionRedeemableUsersPlainArgs $) {
        this.filters = $.filters;
        this.subscriptionId = $.subscriptionId;
        this.tenancyId = $.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSubscriptionRedeemableUsersPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSubscriptionRedeemableUsersPlainArgs $;

        public Builder() {
            $ = new GetSubscriptionRedeemableUsersPlainArgs();
        }

        public Builder(GetSubscriptionRedeemableUsersPlainArgs defaults) {
            $ = new GetSubscriptionRedeemableUsersPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetSubscriptionRedeemableUsersFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSubscriptionRedeemableUsersFilter... filters) {
            return filters(List.of(filters));
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

        public GetSubscriptionRedeemableUsersPlainArgs build() {
            if ($.subscriptionId == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionRedeemableUsersPlainArgs", "subscriptionId");
            }
            if ($.tenancyId == null) {
                throw new MissingRequiredPropertyException("GetSubscriptionRedeemableUsersPlainArgs", "tenancyId");
            }
            return $;
        }
    }

}
