// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetConfigArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConfigArgs Empty = new GetConfigArgs();

    /**
     * Unique Config identifier.
     * 
     */
    @Import(name="configId", required=true)
    private Output<String> configId;

    /**
     * @return Unique Config identifier.
     * 
     */
    public Output<String> configId() {
        return this.configId;
    }

    private GetConfigArgs() {}

    private GetConfigArgs(GetConfigArgs $) {
        this.configId = $.configId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConfigArgs $;

        public Builder() {
            $ = new GetConfigArgs();
        }

        public Builder(GetConfigArgs defaults) {
            $ = new GetConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configId Unique Config identifier.
         * 
         * @return builder
         * 
         */
        public Builder configId(Output<String> configId) {
            $.configId = configId;
            return this;
        }

        /**
         * @param configId Unique Config identifier.
         * 
         * @return builder
         * 
         */
        public Builder configId(String configId) {
            return configId(Output.of(configId));
        }

        public GetConfigArgs build() {
            $.configId = Objects.requireNonNull($.configId, "expected parameter 'configId' to be non-null");
            return $;
        }
    }

}