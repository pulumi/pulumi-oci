// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AnnouncementsService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AnnouncementsService.outputs.GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroupFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup {
    /**
     * @return A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
     * 
     */
    private List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroupFilter> filters;
    /**
     * @return The name of the group. The name must be unique and it cannot be changed. Avoid entering confidential information.
     * 
     */
    private String name;

    private GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup() {}
    /**
     * @return A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
     * 
     */
    public List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroupFilter> filters() {
        return this.filters;
    }
    /**
     * @return The name of the group. The name must be unique and it cannot be changed. Avoid entering confidential information.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroupFilter> filters;
        private String name;
        public Builder() {}
        public Builder(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder filters(List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroupFilter> filters) {
            if (filters == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup", "filters");
            }
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroupFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup", "name");
            }
            this.name = name;
            return this;
        }
        public GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup build() {
            final var _resultValue = new GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup();
            _resultValue.filters = filters;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
