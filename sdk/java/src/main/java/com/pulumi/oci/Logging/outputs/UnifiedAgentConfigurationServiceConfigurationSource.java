// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Logging.outputs.UnifiedAgentConfigurationServiceConfigurationSourceParser;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class UnifiedAgentConfigurationServiceConfigurationSource {
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable List<String> channels;
    /**
     * @return (Updatable) The name key to tag this grok pattern.
     * 
     */
    private @Nullable String name;
    /**
     * @return (Updatable) source parser object.
     * 
     */
    private @Nullable UnifiedAgentConfigurationServiceConfigurationSourceParser parser;
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable List<String> paths;
    /**
     * @return (Updatable) Unified schema logging source type.
     * 
     */
    private String sourceType;

    private UnifiedAgentConfigurationServiceConfigurationSource() {}
    /**
     * @return (Updatable)
     * 
     */
    public List<String> channels() {
        return this.channels == null ? List.of() : this.channels;
    }
    /**
     * @return (Updatable) The name key to tag this grok pattern.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return (Updatable) source parser object.
     * 
     */
    public Optional<UnifiedAgentConfigurationServiceConfigurationSourceParser> parser() {
        return Optional.ofNullable(this.parser);
    }
    /**
     * @return (Updatable)
     * 
     */
    public List<String> paths() {
        return this.paths == null ? List.of() : this.paths;
    }
    /**
     * @return (Updatable) Unified schema logging source type.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(UnifiedAgentConfigurationServiceConfigurationSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> channels;
        private @Nullable String name;
        private @Nullable UnifiedAgentConfigurationServiceConfigurationSourceParser parser;
        private @Nullable List<String> paths;
        private String sourceType;
        public Builder() {}
        public Builder(UnifiedAgentConfigurationServiceConfigurationSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.channels = defaults.channels;
    	      this.name = defaults.name;
    	      this.parser = defaults.parser;
    	      this.paths = defaults.paths;
    	      this.sourceType = defaults.sourceType;
        }

        @CustomType.Setter
        public Builder channels(@Nullable List<String> channels) {
            this.channels = channels;
            return this;
        }
        public Builder channels(String... channels) {
            return channels(List.of(channels));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder parser(@Nullable UnifiedAgentConfigurationServiceConfigurationSourceParser parser) {
            this.parser = parser;
            return this;
        }
        @CustomType.Setter
        public Builder paths(@Nullable List<String> paths) {
            this.paths = paths;
            return this;
        }
        public Builder paths(String... paths) {
            return paths(List.of(paths));
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            this.sourceType = Objects.requireNonNull(sourceType);
            return this;
        }
        public UnifiedAgentConfigurationServiceConfigurationSource build() {
            final var o = new UnifiedAgentConfigurationServiceConfigurationSource();
            o.channels = channels;
            o.name = name;
            o.parser = parser;
            o.paths = paths;
            o.sourceType = sourceType;
            return o;
        }
    }
}