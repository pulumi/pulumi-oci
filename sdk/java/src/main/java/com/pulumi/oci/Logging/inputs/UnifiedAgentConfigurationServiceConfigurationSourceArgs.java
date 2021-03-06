// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Logging.inputs.UnifiedAgentConfigurationServiceConfigurationSourceParserArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class UnifiedAgentConfigurationServiceConfigurationSourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final UnifiedAgentConfigurationServiceConfigurationSourceArgs Empty = new UnifiedAgentConfigurationServiceConfigurationSourceArgs();

    /**
     * (Updatable)
     * 
     */
    @Import(name="channels")
    private @Nullable Output<List<String>> channels;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<List<String>>> channels() {
        return Optional.ofNullable(this.channels);
    }

    /**
     * (Updatable) The name key to tag this grok pattern.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The name key to tag this grok pattern.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) source parser object.
     * 
     */
    @Import(name="parser")
    private @Nullable Output<UnifiedAgentConfigurationServiceConfigurationSourceParserArgs> parser;

    /**
     * @return (Updatable) source parser object.
     * 
     */
    public Optional<Output<UnifiedAgentConfigurationServiceConfigurationSourceParserArgs>> parser() {
        return Optional.ofNullable(this.parser);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="paths")
    private @Nullable Output<List<String>> paths;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<List<String>>> paths() {
        return Optional.ofNullable(this.paths);
    }

    /**
     * (Updatable) Unified schema logging source type.
     * 
     */
    @Import(name="sourceType", required=true)
    private Output<String> sourceType;

    /**
     * @return (Updatable) Unified schema logging source type.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }

    private UnifiedAgentConfigurationServiceConfigurationSourceArgs() {}

    private UnifiedAgentConfigurationServiceConfigurationSourceArgs(UnifiedAgentConfigurationServiceConfigurationSourceArgs $) {
        this.channels = $.channels;
        this.name = $.name;
        this.parser = $.parser;
        this.paths = $.paths;
        this.sourceType = $.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UnifiedAgentConfigurationServiceConfigurationSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UnifiedAgentConfigurationServiceConfigurationSourceArgs $;

        public Builder() {
            $ = new UnifiedAgentConfigurationServiceConfigurationSourceArgs();
        }

        public Builder(UnifiedAgentConfigurationServiceConfigurationSourceArgs defaults) {
            $ = new UnifiedAgentConfigurationServiceConfigurationSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param channels (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder channels(@Nullable Output<List<String>> channels) {
            $.channels = channels;
            return this;
        }

        /**
         * @param channels (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder channels(List<String> channels) {
            return channels(Output.of(channels));
        }

        /**
         * @param channels (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder channels(String... channels) {
            return channels(List.of(channels));
        }

        /**
         * @param name (Updatable) The name key to tag this grok pattern.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name key to tag this grok pattern.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param parser (Updatable) source parser object.
         * 
         * @return builder
         * 
         */
        public Builder parser(@Nullable Output<UnifiedAgentConfigurationServiceConfigurationSourceParserArgs> parser) {
            $.parser = parser;
            return this;
        }

        /**
         * @param parser (Updatable) source parser object.
         * 
         * @return builder
         * 
         */
        public Builder parser(UnifiedAgentConfigurationServiceConfigurationSourceParserArgs parser) {
            return parser(Output.of(parser));
        }

        /**
         * @param paths (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder paths(@Nullable Output<List<String>> paths) {
            $.paths = paths;
            return this;
        }

        /**
         * @param paths (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder paths(List<String> paths) {
            return paths(Output.of(paths));
        }

        /**
         * @param paths (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder paths(String... paths) {
            return paths(List.of(paths));
        }

        /**
         * @param sourceType (Updatable) Unified schema logging source type.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(Output<String> sourceType) {
            $.sourceType = sourceType;
            return this;
        }

        /**
         * @param sourceType (Updatable) Unified schema logging source type.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(String sourceType) {
            return sourceType(Output.of(sourceType));
        }

        public UnifiedAgentConfigurationServiceConfigurationSourceArgs build() {
            $.sourceType = Objects.requireNonNull($.sourceType, "expected parameter 'sourceType' to be non-null");
            return $;
        }
    }

}
