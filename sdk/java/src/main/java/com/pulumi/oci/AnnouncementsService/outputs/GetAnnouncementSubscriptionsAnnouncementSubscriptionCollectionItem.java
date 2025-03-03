// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AnnouncementsService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AnnouncementsService.outputs.GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem {
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A description of the announcement subscription. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return A list of filter groups for the announcement subscription. A filter group is a combination of multiple filters applied to announcements for matching purposes.
     * 
     */
    private List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup> filterGroups;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the announcement subscription.
     * 
     */
    private String id;
    /**
     * @return A message describing the current lifecycle state in more detail. For example, details might provide required or recommended actions for a resource in a Failed state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription.
     * 
     */
    private String onsTopicId;
    /**
     * @return (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
     * 
     */
    private String preferredLanguage;
    /**
     * @return The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
     * 
     */
    private String preferredTimeZone;
    /**
     * @return A filter to return only announcement subscriptions that match the given lifecycle state.
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time that the announcement subscription was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time that the announcement subscription was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    private String timeUpdated;

    private GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem() {}
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A description of the announcement subscription. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return A list of filter groups for the announcement subscription. A filter group is a combination of multiple filters applied to announcements for matching purposes.
     * 
     */
    public List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup> filterGroups() {
        return this.filterGroups;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the announcement subscription.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current lifecycle state in more detail. For example, details might provide required or recommended actions for a resource in a Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription.
     * 
     */
    public String onsTopicId() {
        return this.onsTopicId;
    }
    /**
     * @return (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
     * 
     */
    public String preferredLanguage() {
        return this.preferredLanguage;
    }
    /**
     * @return The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
     * 
     */
    public String preferredTimeZone() {
        return this.preferredTimeZone;
    }
    /**
     * @return A filter to return only announcement subscriptions that match the given lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time that the announcement subscription was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the announcement subscription was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup> filterGroups;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String onsTopicId;
        private String preferredLanguage;
        private String preferredTimeZone;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.filterGroups = defaults.filterGroups;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.onsTopicId = defaults.onsTopicId;
    	      this.preferredLanguage = defaults.preferredLanguage;
    	      this.preferredTimeZone = defaults.preferredTimeZone;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filterGroups(List<GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup> filterGroups) {
            if (filterGroups == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "filterGroups");
            }
            this.filterGroups = filterGroups;
            return this;
        }
        public Builder filterGroups(GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemFilterGroup... filterGroups) {
            return filterGroups(List.of(filterGroups));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder onsTopicId(String onsTopicId) {
            if (onsTopicId == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "onsTopicId");
            }
            this.onsTopicId = onsTopicId;
            return this;
        }
        @CustomType.Setter
        public Builder preferredLanguage(String preferredLanguage) {
            if (preferredLanguage == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "preferredLanguage");
            }
            this.preferredLanguage = preferredLanguage;
            return this;
        }
        @CustomType.Setter
        public Builder preferredTimeZone(String preferredTimeZone) {
            if (preferredTimeZone == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "preferredTimeZone");
            }
            this.preferredTimeZone = preferredTimeZone;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem build() {
            final var _resultValue = new GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.filterGroups = filterGroups;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.onsTopicId = onsTopicId;
            _resultValue.preferredLanguage = preferredLanguage;
            _resultValue.preferredTimeZone = preferredTimeZone;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
