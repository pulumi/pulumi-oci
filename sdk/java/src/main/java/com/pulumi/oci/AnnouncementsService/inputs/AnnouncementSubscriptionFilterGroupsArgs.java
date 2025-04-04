// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AnnouncementsService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AnnouncementsService.inputs.AnnouncementSubscriptionFilterGroupsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AnnouncementSubscriptionFilterGroupsArgs extends com.pulumi.resources.ResourceArgs {

    public static final AnnouncementSubscriptionFilterGroupsArgs Empty = new AnnouncementSubscriptionFilterGroupsArgs();

    /**
     * A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
     * 
     */
    @Import(name="filters", required=true)
    private Output<List<AnnouncementSubscriptionFilterGroupsFilterArgs>> filters;

    /**
     * @return A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
     * 
     */
    public Output<List<AnnouncementSubscriptionFilterGroupsFilterArgs>> filters() {
        return this.filters;
    }

    /**
     * The name of the group. The name must be unique and it cannot be changed. Avoid entering confidential information.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the group. The name must be unique and it cannot be changed. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private AnnouncementSubscriptionFilterGroupsArgs() {}

    private AnnouncementSubscriptionFilterGroupsArgs(AnnouncementSubscriptionFilterGroupsArgs $) {
        this.filters = $.filters;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AnnouncementSubscriptionFilterGroupsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AnnouncementSubscriptionFilterGroupsArgs $;

        public Builder() {
            $ = new AnnouncementSubscriptionFilterGroupsArgs();
        }

        public Builder(AnnouncementSubscriptionFilterGroupsArgs defaults) {
            $ = new AnnouncementSubscriptionFilterGroupsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param filters A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
         * 
         * @return builder
         * 
         */
        public Builder filters(Output<List<AnnouncementSubscriptionFilterGroupsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        /**
         * @param filters A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
         * 
         * @return builder
         * 
         */
        public Builder filters(List<AnnouncementSubscriptionFilterGroupsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        /**
         * @param filters A list of filters against which the Announcements service matches announcements. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
         * 
         * @return builder
         * 
         */
        public Builder filters(AnnouncementSubscriptionFilterGroupsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name The name of the group. The name must be unique and it cannot be changed. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the group. The name must be unique and it cannot be changed. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public AnnouncementSubscriptionFilterGroupsArgs build() {
            if ($.filters == null) {
                throw new MissingRequiredPropertyException("AnnouncementSubscriptionFilterGroupsArgs", "filters");
            }
            return $;
        }
    }

}
