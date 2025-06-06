// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LogAnalytics.inputs.NamespaceStorageArchivalConfigArchivingConfigurationArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NamespaceStorageArchivalConfigState extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceStorageArchivalConfigState Empty = new NamespaceStorageArchivalConfigState();

    /**
     * (Updatable) This is the configuration for data archiving in object storage
     * 
     */
    @Import(name="archivingConfiguration")
    private @Nullable Output<NamespaceStorageArchivalConfigArchivingConfigurationArgs> archivingConfiguration;

    /**
     * @return (Updatable) This is the configuration for data archiving in object storage
     * 
     */
    public Optional<Output<NamespaceStorageArchivalConfigArchivingConfigurationArgs>> archivingConfiguration() {
        return Optional.ofNullable(this.archivingConfiguration);
    }

    /**
     * This indicates if old data can be archived for a tenancy
     * 
     */
    @Import(name="isArchivingEnabled")
    private @Nullable Output<Boolean> isArchivingEnabled;

    /**
     * @return This indicates if old data can be archived for a tenancy
     * 
     */
    public Optional<Output<Boolean>> isArchivingEnabled() {
        return Optional.ofNullable(this.isArchivingEnabled);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    private NamespaceStorageArchivalConfigState() {}

    private NamespaceStorageArchivalConfigState(NamespaceStorageArchivalConfigState $) {
        this.archivingConfiguration = $.archivingConfiguration;
        this.isArchivingEnabled = $.isArchivingEnabled;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceStorageArchivalConfigState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceStorageArchivalConfigState $;

        public Builder() {
            $ = new NamespaceStorageArchivalConfigState();
        }

        public Builder(NamespaceStorageArchivalConfigState defaults) {
            $ = new NamespaceStorageArchivalConfigState(Objects.requireNonNull(defaults));
        }

        /**
         * @param archivingConfiguration (Updatable) This is the configuration for data archiving in object storage
         * 
         * @return builder
         * 
         */
        public Builder archivingConfiguration(@Nullable Output<NamespaceStorageArchivalConfigArchivingConfigurationArgs> archivingConfiguration) {
            $.archivingConfiguration = archivingConfiguration;
            return this;
        }

        /**
         * @param archivingConfiguration (Updatable) This is the configuration for data archiving in object storage
         * 
         * @return builder
         * 
         */
        public Builder archivingConfiguration(NamespaceStorageArchivalConfigArchivingConfigurationArgs archivingConfiguration) {
            return archivingConfiguration(Output.of(archivingConfiguration));
        }

        /**
         * @param isArchivingEnabled This indicates if old data can be archived for a tenancy
         * 
         * @return builder
         * 
         */
        public Builder isArchivingEnabled(@Nullable Output<Boolean> isArchivingEnabled) {
            $.isArchivingEnabled = isArchivingEnabled;
            return this;
        }

        /**
         * @param isArchivingEnabled This indicates if old data can be archived for a tenancy
         * 
         * @return builder
         * 
         */
        public Builder isArchivingEnabled(Boolean isArchivingEnabled) {
            return isArchivingEnabled(Output.of(isArchivingEnabled));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public NamespaceStorageArchivalConfigState build() {
            return $;
        }
    }

}
