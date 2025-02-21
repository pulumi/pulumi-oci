// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AnnouncementsService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AnnouncementsService.outputs.GetAnnouncementSubscriptionsAnnouncementSubscriptionCollection;
import com.pulumi.oci.AnnouncementsService.outputs.GetAnnouncementSubscriptionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAnnouncementSubscriptionsResult {
    /**
     * @return The list of announcement_subscription_collection.
     * 
     */
    private List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollection> announcementSubscriptionCollections;
    /**
     * @return The OCID of the compartment that contains the announcement subscription.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name for the announcement subscription. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetAnnouncementSubscriptionsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the announcement subscription.
     * 
     */
    private @Nullable String id;
    /**
     * @return The current lifecycle state of the announcement subscription.
     * 
     */
    private @Nullable String state;

    private GetAnnouncementSubscriptionsResult() {}
    /**
     * @return The list of announcement_subscription_collection.
     * 
     */
    public List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollection> announcementSubscriptionCollections() {
        return this.announcementSubscriptionCollections;
    }
    /**
     * @return The OCID of the compartment that contains the announcement subscription.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name for the announcement subscription. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetAnnouncementSubscriptionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the announcement subscription.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current lifecycle state of the announcement subscription.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAnnouncementSubscriptionsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollection> announcementSubscriptionCollections;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetAnnouncementSubscriptionsFilter> filters;
        private @Nullable String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetAnnouncementSubscriptionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.announcementSubscriptionCollections = defaults.announcementSubscriptionCollections;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder announcementSubscriptionCollections(List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollection> announcementSubscriptionCollections) {
            if (announcementSubscriptionCollections == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsResult", "announcementSubscriptionCollections");
            }
            this.announcementSubscriptionCollections = announcementSubscriptionCollections;
            return this;
        }
        public Builder announcementSubscriptionCollections(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollection... announcementSubscriptionCollections) {
            return announcementSubscriptionCollections(List.of(announcementSubscriptionCollections));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetAnnouncementSubscriptionsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetAnnouncementSubscriptionsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetAnnouncementSubscriptionsResult build() {
            final var _resultValue = new GetAnnouncementSubscriptionsResult();
            _resultValue.announcementSubscriptionCollections = announcementSubscriptionCollections;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
