// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class NamespaceStorageArchivalConfigArchivingConfiguration {
    /**
     * @return (Updatable) This is the duration data in active storage before data is archived, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    private @Nullable String activeStorageDuration;
    /**
     * @return (Updatable) This is the duration before archived data is deleted from object storage, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    private @Nullable String archivalStorageDuration;

    private NamespaceStorageArchivalConfigArchivingConfiguration() {}
    /**
     * @return (Updatable) This is the duration data in active storage before data is archived, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    public Optional<String> activeStorageDuration() {
        return Optional.ofNullable(this.activeStorageDuration);
    }
    /**
     * @return (Updatable) This is the duration before archived data is deleted from object storage, as described in https://en.wikipedia.org/wiki/ISO_8601#Durations The largest supported unit is D, e.g. P365D (not P1Y) or P14D (not P2W).
     * 
     */
    public Optional<String> archivalStorageDuration() {
        return Optional.ofNullable(this.archivalStorageDuration);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NamespaceStorageArchivalConfigArchivingConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String activeStorageDuration;
        private @Nullable String archivalStorageDuration;
        public Builder() {}
        public Builder(NamespaceStorageArchivalConfigArchivingConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.activeStorageDuration = defaults.activeStorageDuration;
    	      this.archivalStorageDuration = defaults.archivalStorageDuration;
        }

        @CustomType.Setter
        public Builder activeStorageDuration(@Nullable String activeStorageDuration) {

            this.activeStorageDuration = activeStorageDuration;
            return this;
        }
        @CustomType.Setter
        public Builder archivalStorageDuration(@Nullable String archivalStorageDuration) {

            this.archivalStorageDuration = archivalStorageDuration;
            return this;
        }
        public NamespaceStorageArchivalConfigArchivingConfiguration build() {
            final var _resultValue = new NamespaceStorageArchivalConfigArchivingConfiguration();
            _resultValue.activeStorageDuration = activeStorageDuration;
            _resultValue.archivalStorageDuration = archivalStorageDuration;
            return _resultValue;
        }
    }
}
