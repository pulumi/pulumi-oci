// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Logging.inputs.UnifiedAgentConfigurationServiceConfigurationDestinationArgs;
import com.pulumi.oci.Logging.inputs.UnifiedAgentConfigurationServiceConfigurationSourceArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class UnifiedAgentConfigurationServiceConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final UnifiedAgentConfigurationServiceConfigurationArgs Empty = new UnifiedAgentConfigurationServiceConfigurationArgs();

    /**
     * (Updatable) Type of Unified Agent service configuration.
     * 
     */
    @Import(name="configurationType", required=true)
    private Output<String> configurationType;

    /**
     * @return (Updatable) Type of Unified Agent service configuration.
     * 
     */
    public Output<String> configurationType() {
        return this.configurationType;
    }

    /**
     * (Updatable) Logging destination object.
     * 
     */
    @Import(name="destination", required=true)
    private Output<UnifiedAgentConfigurationServiceConfigurationDestinationArgs> destination;

    /**
     * @return (Updatable) Logging destination object.
     * 
     */
    public Output<UnifiedAgentConfigurationServiceConfigurationDestinationArgs> destination() {
        return this.destination;
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="sources", required=true)
    private Output<List<UnifiedAgentConfigurationServiceConfigurationSourceArgs>> sources;

    /**
     * @return (Updatable)
     * 
     */
    public Output<List<UnifiedAgentConfigurationServiceConfigurationSourceArgs>> sources() {
        return this.sources;
    }

    private UnifiedAgentConfigurationServiceConfigurationArgs() {}

    private UnifiedAgentConfigurationServiceConfigurationArgs(UnifiedAgentConfigurationServiceConfigurationArgs $) {
        this.configurationType = $.configurationType;
        this.destination = $.destination;
        this.sources = $.sources;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UnifiedAgentConfigurationServiceConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UnifiedAgentConfigurationServiceConfigurationArgs $;

        public Builder() {
            $ = new UnifiedAgentConfigurationServiceConfigurationArgs();
        }

        public Builder(UnifiedAgentConfigurationServiceConfigurationArgs defaults) {
            $ = new UnifiedAgentConfigurationServiceConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configurationType (Updatable) Type of Unified Agent service configuration.
         * 
         * @return builder
         * 
         */
        public Builder configurationType(Output<String> configurationType) {
            $.configurationType = configurationType;
            return this;
        }

        /**
         * @param configurationType (Updatable) Type of Unified Agent service configuration.
         * 
         * @return builder
         * 
         */
        public Builder configurationType(String configurationType) {
            return configurationType(Output.of(configurationType));
        }

        /**
         * @param destination (Updatable) Logging destination object.
         * 
         * @return builder
         * 
         */
        public Builder destination(Output<UnifiedAgentConfigurationServiceConfigurationDestinationArgs> destination) {
            $.destination = destination;
            return this;
        }

        /**
         * @param destination (Updatable) Logging destination object.
         * 
         * @return builder
         * 
         */
        public Builder destination(UnifiedAgentConfigurationServiceConfigurationDestinationArgs destination) {
            return destination(Output.of(destination));
        }

        /**
         * @param sources (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sources(Output<List<UnifiedAgentConfigurationServiceConfigurationSourceArgs>> sources) {
            $.sources = sources;
            return this;
        }

        /**
         * @param sources (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sources(List<UnifiedAgentConfigurationServiceConfigurationSourceArgs> sources) {
            return sources(Output.of(sources));
        }

        /**
         * @param sources (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sources(UnifiedAgentConfigurationServiceConfigurationSourceArgs... sources) {
            return sources(List.of(sources));
        }

        public UnifiedAgentConfigurationServiceConfigurationArgs build() {
            $.configurationType = Objects.requireNonNull($.configurationType, "expected parameter 'configurationType' to be non-null");
            $.destination = Objects.requireNonNull($.destination, "expected parameter 'destination' to be non-null");
            $.sources = Objects.requireNonNull($.sources, "expected parameter 'sources' to be non-null");
            return $;
        }
    }

}