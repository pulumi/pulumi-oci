// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class UnifiedAgentConfigurationServiceConfigurationDestinationArgs extends com.pulumi.resources.ResourceArgs {

    public static final UnifiedAgentConfigurationServiceConfigurationDestinationArgs Empty = new UnifiedAgentConfigurationServiceConfigurationDestinationArgs();

    /**
     * (Updatable) The OCID of the resource.
     * 
     */
    @Import(name="logObjectId", required=true)
    private Output<String> logObjectId;

    /**
     * @return (Updatable) The OCID of the resource.
     * 
     */
    public Output<String> logObjectId() {
        return this.logObjectId;
    }

    private UnifiedAgentConfigurationServiceConfigurationDestinationArgs() {}

    private UnifiedAgentConfigurationServiceConfigurationDestinationArgs(UnifiedAgentConfigurationServiceConfigurationDestinationArgs $) {
        this.logObjectId = $.logObjectId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UnifiedAgentConfigurationServiceConfigurationDestinationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UnifiedAgentConfigurationServiceConfigurationDestinationArgs $;

        public Builder() {
            $ = new UnifiedAgentConfigurationServiceConfigurationDestinationArgs();
        }

        public Builder(UnifiedAgentConfigurationServiceConfigurationDestinationArgs defaults) {
            $ = new UnifiedAgentConfigurationServiceConfigurationDestinationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param logObjectId (Updatable) The OCID of the resource.
         * 
         * @return builder
         * 
         */
        public Builder logObjectId(Output<String> logObjectId) {
            $.logObjectId = logObjectId;
            return this;
        }

        /**
         * @param logObjectId (Updatable) The OCID of the resource.
         * 
         * @return builder
         * 
         */
        public Builder logObjectId(String logObjectId) {
            return logObjectId(Output.of(logObjectId));
        }

        public UnifiedAgentConfigurationServiceConfigurationDestinationArgs build() {
            $.logObjectId = Objects.requireNonNull($.logObjectId, "expected parameter 'logObjectId' to be non-null");
            return $;
        }
    }

}