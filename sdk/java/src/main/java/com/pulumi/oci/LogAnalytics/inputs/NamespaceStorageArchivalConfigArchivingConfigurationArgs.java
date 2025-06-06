// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NamespaceStorageArchivalConfigArchivingConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceStorageArchivalConfigArchivingConfigurationArgs Empty = new NamespaceStorageArchivalConfigArchivingConfigurationArgs();

    /**
     * (Updatable) This is the duration data in active storage before data is archived, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    @Import(name="activeStorageDuration")
    private @Nullable Output<String> activeStorageDuration;

    /**
     * @return (Updatable) This is the duration data in active storage before data is archived, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    public Optional<Output<String>> activeStorageDuration() {
        return Optional.ofNullable(this.activeStorageDuration);
    }

    /**
     * (Updatable) This is the duration before archived data is deleted from object storage, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    @Import(name="archivalStorageDuration")
    private @Nullable Output<String> archivalStorageDuration;

    /**
     * @return (Updatable) This is the duration before archived data is deleted from object storage, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    public Optional<Output<String>> archivalStorageDuration() {
        return Optional.ofNullable(this.archivalStorageDuration);
    }

    private NamespaceStorageArchivalConfigArchivingConfigurationArgs() {}

    private NamespaceStorageArchivalConfigArchivingConfigurationArgs(NamespaceStorageArchivalConfigArchivingConfigurationArgs $) {
        this.activeStorageDuration = $.activeStorageDuration;
        this.archivalStorageDuration = $.archivalStorageDuration;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceStorageArchivalConfigArchivingConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceStorageArchivalConfigArchivingConfigurationArgs $;

        public Builder() {
            $ = new NamespaceStorageArchivalConfigArchivingConfigurationArgs();
        }

        public Builder(NamespaceStorageArchivalConfigArchivingConfigurationArgs defaults) {
            $ = new NamespaceStorageArchivalConfigArchivingConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param activeStorageDuration (Updatable) This is the duration data in active storage before data is archived, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
         * 
         * @return builder
         * 
         */
        public Builder activeStorageDuration(@Nullable Output<String> activeStorageDuration) {
            $.activeStorageDuration = activeStorageDuration;
            return this;
        }

        /**
         * @param activeStorageDuration (Updatable) This is the duration data in active storage before data is archived, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
         * 
         * @return builder
         * 
         */
        public Builder activeStorageDuration(String activeStorageDuration) {
            return activeStorageDuration(Output.of(activeStorageDuration));
        }

        /**
         * @param archivalStorageDuration (Updatable) This is the duration before archived data is deleted from object storage, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
         * 
         * @return builder
         * 
         */
        public Builder archivalStorageDuration(@Nullable Output<String> archivalStorageDuration) {
            $.archivalStorageDuration = archivalStorageDuration;
            return this;
        }

        /**
         * @param archivalStorageDuration (Updatable) This is the duration before archived data is deleted from object storage, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
         * 
         * @return builder
         * 
         */
        public Builder archivalStorageDuration(String archivalStorageDuration) {
            return archivalStorageDuration(Output.of(archivalStorageDuration));
        }

        public NamespaceStorageArchivalConfigArchivingConfigurationArgs build() {
            return $;
        }
    }

}
