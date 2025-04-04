// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AnnouncementsService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AnnouncementsService.inputs.AnnouncementSubscriptionFilterGroupsArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AnnouncementSubscriptionArgs extends com.pulumi.resources.ResourceArgs {

    public static final AnnouncementSubscriptionArgs Empty = new AnnouncementSubscriptionArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A description of the announcement subscription. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A description of the announcement subscription. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
     * 
     */
    @Import(name="filterGroups")
    private @Nullable Output<AnnouncementSubscriptionFilterGroupsArgs> filterGroups;

    /**
     * @return A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
     * 
     */
    public Optional<Output<AnnouncementSubscriptionFilterGroupsArgs>> filterGroups() {
        return Optional.ofNullable(this.filterGroups);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
     * 
     */
    @Import(name="onsTopicId", required=true)
    private Output<String> onsTopicId;

    /**
     * @return (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
     * 
     */
    public Output<String> onsTopicId() {
        return this.onsTopicId;
    }

    /**
     * (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
     * 
     */
    @Import(name="preferredLanguage")
    private @Nullable Output<String> preferredLanguage;

    /**
     * @return (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
     * 
     */
    public Optional<Output<String>> preferredLanguage() {
        return Optional.ofNullable(this.preferredLanguage);
    }

    /**
     * (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="preferredTimeZone")
    private @Nullable Output<String> preferredTimeZone;

    /**
     * @return (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> preferredTimeZone() {
        return Optional.ofNullable(this.preferredTimeZone);
    }

    private AnnouncementSubscriptionArgs() {}

    private AnnouncementSubscriptionArgs(AnnouncementSubscriptionArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.filterGroups = $.filterGroups;
        this.freeformTags = $.freeformTags;
        this.onsTopicId = $.onsTopicId;
        this.preferredLanguage = $.preferredLanguage;
        this.preferredTimeZone = $.preferredTimeZone;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AnnouncementSubscriptionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AnnouncementSubscriptionArgs $;

        public Builder() {
            $ = new AnnouncementSubscriptionArgs();
        }

        public Builder(AnnouncementSubscriptionArgs defaults) {
            $ = new AnnouncementSubscriptionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the announcement subscription.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A description of the announcement subscription. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A description of the announcement subscription. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the announcement subscription. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param filterGroups A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
         * 
         * @return builder
         * 
         */
        public Builder filterGroups(@Nullable Output<AnnouncementSubscriptionFilterGroupsArgs> filterGroups) {
            $.filterGroups = filterGroups;
            return this;
        }

        /**
         * @param filterGroups A list of filter groups for the announcement subscription. A filter group combines one or more filters that the Announcements service applies to announcements for matching purposes.
         * 
         * @return builder
         * 
         */
        public Builder filterGroups(AnnouncementSubscriptionFilterGroupsArgs filterGroups) {
            return filterGroups(Output.of(filterGroups));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param onsTopicId (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
         * 
         * @return builder
         * 
         */
        public Builder onsTopicId(Output<String> onsTopicId) {
            $.onsTopicId = onsTopicId;
            return this;
        }

        /**
         * @param onsTopicId (Updatable) The OCID of the Notifications service topic that is the target for publishing announcements that match the configured announcement subscription. The caller of the operation needs the ONS_TOPIC_PUBLISH permission for the targeted Notifications service topic. For more information about Notifications permissions, see [Details for Notifications](https://docs.cloud.oracle.com/iaas/Content/Identity/policyreference/notificationpolicyreference.htm).
         * 
         * @return builder
         * 
         */
        public Builder onsTopicId(String onsTopicId) {
            return onsTopicId(Output.of(onsTopicId));
        }

        /**
         * @param preferredLanguage (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
         * 
         * @return builder
         * 
         */
        public Builder preferredLanguage(@Nullable Output<String> preferredLanguage) {
            $.preferredLanguage = preferredLanguage;
            return this;
        }

        /**
         * @param preferredLanguage (Updatable) (For announcement subscriptions with SaaS configured as the platform type or Oracle Fusion Applications as the service, or both, only) The language in which the user prefers to receive emailed announcements. Specify the preference with a value that uses the x-obmcs-human-language format. For example fr-FR.
         * 
         * @return builder
         * 
         */
        public Builder preferredLanguage(String preferredLanguage) {
            return preferredLanguage(Output.of(preferredLanguage));
        }

        /**
         * @param preferredTimeZone (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder preferredTimeZone(@Nullable Output<String> preferredTimeZone) {
            $.preferredTimeZone = preferredTimeZone;
            return this;
        }

        /**
         * @param preferredTimeZone (Updatable) The time zone in which the user prefers to receive announcements. Specify the preference with a value that uses the IANA Time Zone Database format (x-obmcs-time-zone). For example - America/Los_Angeles
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder preferredTimeZone(String preferredTimeZone) {
            return preferredTimeZone(Output.of(preferredTimeZone));
        }

        public AnnouncementSubscriptionArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("AnnouncementSubscriptionArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("AnnouncementSubscriptionArgs", "displayName");
            }
            if ($.onsTopicId == null) {
                throw new MissingRequiredPropertyException("AnnouncementSubscriptionArgs", "onsTopicId");
            }
            return $;
        }
    }

}
