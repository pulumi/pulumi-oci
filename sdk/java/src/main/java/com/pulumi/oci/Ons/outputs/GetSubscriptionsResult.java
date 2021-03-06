// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ons.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Ons.outputs.GetSubscriptionsFilter;
import com.pulumi.oci.Ons.outputs.GetSubscriptionsSubscription;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSubscriptionsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetSubscriptionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of subscriptions.
     * 
     */
    private final List<GetSubscriptionsSubscription> subscriptions;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated topic.
     * 
     */
    private final @Nullable String topicId;

    @CustomType.Constructor
    private GetSubscriptionsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetSubscriptionsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("subscriptions") List<GetSubscriptionsSubscription> subscriptions,
        @CustomType.Parameter("topicId") @Nullable String topicId) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.subscriptions = subscriptions;
        this.topicId = topicId;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the subscription.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetSubscriptionsFilter> filters() {
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
     * @return The list of subscriptions.
     * 
     */
    public List<GetSubscriptionsSubscription> subscriptions() {
        return this.subscriptions;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated topic.
     * 
     */
    public Optional<String> topicId() {
        return Optional.ofNullable(this.topicId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetSubscriptionsFilter> filters;
        private String id;
        private List<GetSubscriptionsSubscription> subscriptions;
        private @Nullable String topicId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSubscriptionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.subscriptions = defaults.subscriptions;
    	      this.topicId = defaults.topicId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetSubscriptionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSubscriptionsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder subscriptions(List<GetSubscriptionsSubscription> subscriptions) {
            this.subscriptions = Objects.requireNonNull(subscriptions);
            return this;
        }
        public Builder subscriptions(GetSubscriptionsSubscription... subscriptions) {
            return subscriptions(List.of(subscriptions));
        }
        public Builder topicId(@Nullable String topicId) {
            this.topicId = topicId;
            return this;
        }        public GetSubscriptionsResult build() {
            return new GetSubscriptionsResult(compartmentId, filters, id, subscriptions, topicId);
        }
    }
}
