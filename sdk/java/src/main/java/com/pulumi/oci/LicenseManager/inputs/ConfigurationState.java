// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LicenseManager.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigurationState extends com.pulumi.resources.ResourceArgs {

    public static final ConfigurationState Empty = new ConfigurationState();

    /**
     * (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) List of email IDs associated with the configuration.
     * 
     */
    @Import(name="emailIds")
    private @Nullable Output<List<String>> emailIds;

    /**
     * @return (Updatable) List of email IDs associated with the configuration.
     * 
     */
    public Optional<Output<List<String>>> emailIds() {
        return Optional.ofNullable(this.emailIds);
    }

    /**
     * The time the configuration was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the configuration was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the configuration was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the configuration was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ConfigurationState() {}

    private ConfigurationState(ConfigurationState $) {
        this.compartmentId = $.compartmentId;
        this.emailIds = $.emailIds;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigurationState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigurationState $;

        public Builder() {
            $ = new ConfigurationState();
        }

        public Builder(ConfigurationState defaults) {
            $ = new ConfigurationState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param emailIds (Updatable) List of email IDs associated with the configuration.
         * 
         * @return builder
         * 
         */
        public Builder emailIds(@Nullable Output<List<String>> emailIds) {
            $.emailIds = emailIds;
            return this;
        }

        /**
         * @param emailIds (Updatable) List of email IDs associated with the configuration.
         * 
         * @return builder
         * 
         */
        public Builder emailIds(List<String> emailIds) {
            return emailIds(Output.of(emailIds));
        }

        /**
         * @param emailIds (Updatable) List of email IDs associated with the configuration.
         * 
         * @return builder
         * 
         */
        public Builder emailIds(String... emailIds) {
            return emailIds(List.of(emailIds));
        }

        /**
         * @param timeCreated The time the configuration was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the configuration was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the configuration was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the configuration was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ConfigurationState build() {
            return $;
        }
    }

}