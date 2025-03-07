// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.UsageProxy.outputs.GetSubscriptionRedeemableUsersFilter;
import com.pulumi.oci.UsageProxy.outputs.GetSubscriptionRedeemableUsersRedeemableUserCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetSubscriptionRedeemableUsersResult {
    private @Nullable List<GetSubscriptionRedeemableUsersFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of redeemable_user_collection.
     * 
     */
    private List<GetSubscriptionRedeemableUsersRedeemableUserCollection> redeemableUserCollections;
    private String subscriptionId;
    private String tenancyId;

    private GetSubscriptionRedeemableUsersResult() {}
    public List<GetSubscriptionRedeemableUsersFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of redeemable_user_collection.
     * 
     */
    public List<GetSubscriptionRedeemableUsersRedeemableUserCollection> redeemableUserCollections() {
        return this.redeemableUserCollections;
    }
    public String subscriptionId() {
        return this.subscriptionId;
    }
    public String tenancyId() {
        return this.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionRedeemableUsersResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetSubscriptionRedeemableUsersFilter> filters;
        private String id;
        private List<GetSubscriptionRedeemableUsersRedeemableUserCollection> redeemableUserCollections;
        private String subscriptionId;
        private String tenancyId;
        public Builder() {}
        public Builder(GetSubscriptionRedeemableUsersResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.redeemableUserCollections = defaults.redeemableUserCollections;
    	      this.subscriptionId = defaults.subscriptionId;
    	      this.tenancyId = defaults.tenancyId;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetSubscriptionRedeemableUsersFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSubscriptionRedeemableUsersFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionRedeemableUsersResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder redeemableUserCollections(List<GetSubscriptionRedeemableUsersRedeemableUserCollection> redeemableUserCollections) {
            if (redeemableUserCollections == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionRedeemableUsersResult", "redeemableUserCollections");
            }
            this.redeemableUserCollections = redeemableUserCollections;
            return this;
        }
        public Builder redeemableUserCollections(GetSubscriptionRedeemableUsersRedeemableUserCollection... redeemableUserCollections) {
            return redeemableUserCollections(List.of(redeemableUserCollections));
        }
        @CustomType.Setter
        public Builder subscriptionId(String subscriptionId) {
            if (subscriptionId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionRedeemableUsersResult", "subscriptionId");
            }
            this.subscriptionId = subscriptionId;
            return this;
        }
        @CustomType.Setter
        public Builder tenancyId(String tenancyId) {
            if (tenancyId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionRedeemableUsersResult", "tenancyId");
            }
            this.tenancyId = tenancyId;
            return this;
        }
        public GetSubscriptionRedeemableUsersResult build() {
            final var _resultValue = new GetSubscriptionRedeemableUsersResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.redeemableUserCollections = redeemableUserCollections;
            _resultValue.subscriptionId = subscriptionId;
            _resultValue.tenancyId = tenancyId;
            return _resultValue;
        }
    }
}
