// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetStreamDistributionChannelPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamDistributionChannelPlainArgs Empty = new GetStreamDistributionChannelPlainArgs();

    /**
     * Unique Stream Distribution Channel path identifier.
     * 
     */
    @Import(name="streamDistributionChannelId", required=true)
    private String streamDistributionChannelId;

    /**
     * @return Unique Stream Distribution Channel path identifier.
     * 
     */
    public String streamDistributionChannelId() {
        return this.streamDistributionChannelId;
    }

    private GetStreamDistributionChannelPlainArgs() {}

    private GetStreamDistributionChannelPlainArgs(GetStreamDistributionChannelPlainArgs $) {
        this.streamDistributionChannelId = $.streamDistributionChannelId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamDistributionChannelPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamDistributionChannelPlainArgs $;

        public Builder() {
            $ = new GetStreamDistributionChannelPlainArgs();
        }

        public Builder(GetStreamDistributionChannelPlainArgs defaults) {
            $ = new GetStreamDistributionChannelPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param streamDistributionChannelId Unique Stream Distribution Channel path identifier.
         * 
         * @return builder
         * 
         */
        public Builder streamDistributionChannelId(String streamDistributionChannelId) {
            $.streamDistributionChannelId = streamDistributionChannelId;
            return this;
        }

        public GetStreamDistributionChannelPlainArgs build() {
            $.streamDistributionChannelId = Objects.requireNonNull($.streamDistributionChannelId, "expected parameter 'streamDistributionChannelId' to be non-null");
            return $;
        }
    }

}