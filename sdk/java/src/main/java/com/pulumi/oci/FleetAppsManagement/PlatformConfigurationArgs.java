// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.PlatformConfigurationConfigCategoryDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PlatformConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final PlatformConfigurationArgs Empty = new PlatformConfigurationArgs();

    /**
     * (Updatable) Compartment OCID
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment OCID
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Config Category Details.
     * 
     */
    @Import(name="configCategoryDetails", required=true)
    private Output<PlatformConfigurationConfigCategoryDetailsArgs> configCategoryDetails;

    /**
     * @return (Updatable) Config Category Details.
     * 
     */
    public Output<PlatformConfigurationConfigCategoryDetailsArgs> configCategoryDetails() {
        return this.configCategoryDetails;
    }

    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    private PlatformConfigurationArgs() {}

    private PlatformConfigurationArgs(PlatformConfigurationArgs $) {
        this.compartmentId = $.compartmentId;
        this.configCategoryDetails = $.configCategoryDetails;
        this.description = $.description;
        this.displayName = $.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PlatformConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PlatformConfigurationArgs $;

        public Builder() {
            $ = new PlatformConfigurationArgs();
        }

        public Builder(PlatformConfigurationArgs defaults) {
            $ = new PlatformConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param configCategoryDetails (Updatable) Config Category Details.
         * 
         * @return builder
         * 
         */
        public Builder configCategoryDetails(Output<PlatformConfigurationConfigCategoryDetailsArgs> configCategoryDetails) {
            $.configCategoryDetails = configCategoryDetails;
            return this;
        }

        /**
         * @param configCategoryDetails (Updatable) Config Category Details.
         * 
         * @return builder
         * 
         */
        public Builder configCategoryDetails(PlatformConfigurationConfigCategoryDetailsArgs configCategoryDetails) {
            return configCategoryDetails(Output.of(configCategoryDetails));
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public PlatformConfigurationArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("PlatformConfigurationArgs", "compartmentId");
            }
            if ($.configCategoryDetails == null) {
                throw new MissingRequiredPropertyException("PlatformConfigurationArgs", "configCategoryDetails");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("PlatformConfigurationArgs", "displayName");
            }
            return $;
        }
    }

}
