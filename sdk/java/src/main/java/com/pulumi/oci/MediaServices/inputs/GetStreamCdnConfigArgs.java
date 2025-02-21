// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetStreamCdnConfigArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamCdnConfigArgs Empty = new GetStreamCdnConfigArgs();

    /**
     * Unique StreamCdnConfig identifier.
     * 
     */
    @Import(name="streamCdnConfigId", required=true)
    private Output<String> streamCdnConfigId;

    /**
     * @return Unique StreamCdnConfig identifier.
     * 
     */
    public Output<String> streamCdnConfigId() {
        return this.streamCdnConfigId;
    }

    private GetStreamCdnConfigArgs() {}

    private GetStreamCdnConfigArgs(GetStreamCdnConfigArgs $) {
        this.streamCdnConfigId = $.streamCdnConfigId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamCdnConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamCdnConfigArgs $;

        public Builder() {
            $ = new GetStreamCdnConfigArgs();
        }

        public Builder(GetStreamCdnConfigArgs defaults) {
            $ = new GetStreamCdnConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param streamCdnConfigId Unique StreamCdnConfig identifier.
         * 
         * @return builder
         * 
         */
        public Builder streamCdnConfigId(Output<String> streamCdnConfigId) {
            $.streamCdnConfigId = streamCdnConfigId;
            return this;
        }

        /**
         * @param streamCdnConfigId Unique StreamCdnConfig identifier.
         * 
         * @return builder
         * 
         */
        public Builder streamCdnConfigId(String streamCdnConfigId) {
            return streamCdnConfigId(Output.of(streamCdnConfigId));
        }

        public GetStreamCdnConfigArgs build() {
            if ($.streamCdnConfigId == null) {
                throw new MissingRequiredPropertyException("GetStreamCdnConfigArgs", "streamCdnConfigId");
            }
            return $;
        }
    }

}
