// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.FleetNotificationPreferencesPreferencesArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FleetNotificationPreferencesArgs extends com.pulumi.resources.ResourceArgs {

    public static final FleetNotificationPreferencesArgs Empty = new FleetNotificationPreferencesArgs();

    /**
     * (Updatable) Compartment ID the topic belongs to.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment ID the topic belongs to.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Preferences to send notifications on the fleet activities.
     * 
     */
    @Import(name="preferences")
    private @Nullable Output<FleetNotificationPreferencesPreferencesArgs> preferences;

    /**
     * @return (Updatable) Preferences to send notifications on the fleet activities.
     * 
     */
    public Optional<Output<FleetNotificationPreferencesPreferencesArgs>> preferences() {
        return Optional.ofNullable(this.preferences);
    }

    /**
     * (Updatable) Topic Id where the notifications will be directed. A topic is a communication channel for sending messages on chosen events to subscriptions.
     * 
     */
    @Import(name="topicId", required=true)
    private Output<String> topicId;

    /**
     * @return (Updatable) Topic Id where the notifications will be directed. A topic is a communication channel for sending messages on chosen events to subscriptions.
     * 
     */
    public Output<String> topicId() {
        return this.topicId;
    }

    private FleetNotificationPreferencesArgs() {}

    private FleetNotificationPreferencesArgs(FleetNotificationPreferencesArgs $) {
        this.compartmentId = $.compartmentId;
        this.preferences = $.preferences;
        this.topicId = $.topicId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FleetNotificationPreferencesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FleetNotificationPreferencesArgs $;

        public Builder() {
            $ = new FleetNotificationPreferencesArgs();
        }

        public Builder(FleetNotificationPreferencesArgs defaults) {
            $ = new FleetNotificationPreferencesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment ID the topic belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment ID the topic belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param preferences (Updatable) Preferences to send notifications on the fleet activities.
         * 
         * @return builder
         * 
         */
        public Builder preferences(@Nullable Output<FleetNotificationPreferencesPreferencesArgs> preferences) {
            $.preferences = preferences;
            return this;
        }

        /**
         * @param preferences (Updatable) Preferences to send notifications on the fleet activities.
         * 
         * @return builder
         * 
         */
        public Builder preferences(FleetNotificationPreferencesPreferencesArgs preferences) {
            return preferences(Output.of(preferences));
        }

        /**
         * @param topicId (Updatable) Topic Id where the notifications will be directed. A topic is a communication channel for sending messages on chosen events to subscriptions.
         * 
         * @return builder
         * 
         */
        public Builder topicId(Output<String> topicId) {
            $.topicId = topicId;
            return this;
        }

        /**
         * @param topicId (Updatable) Topic Id where the notifications will be directed. A topic is a communication channel for sending messages on chosen events to subscriptions.
         * 
         * @return builder
         * 
         */
        public Builder topicId(String topicId) {
            return topicId(Output.of(topicId));
        }

        public FleetNotificationPreferencesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("FleetNotificationPreferencesArgs", "compartmentId");
            }
            if ($.topicId == null) {
                throw new MissingRequiredPropertyException("FleetNotificationPreferencesArgs", "topicId");
            }
            return $;
        }
    }

}
