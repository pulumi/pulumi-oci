// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetMediaAssetDistributionChannelAttachmentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMediaAssetDistributionChannelAttachmentArgs Empty = new GetMediaAssetDistributionChannelAttachmentArgs();

    /**
     * Unique DistributionChannel identifier.
     * 
     */
    @Import(name="distributionChannelId", required=true)
    private Output<String> distributionChannelId;

    /**
     * @return Unique DistributionChannel identifier.
     * 
     */
    public Output<String> distributionChannelId() {
        return this.distributionChannelId;
    }

    /**
     * Unique MediaAsset identifier
     * 
     */
    @Import(name="mediaAssetId", required=true)
    private Output<String> mediaAssetId;

    /**
     * @return Unique MediaAsset identifier
     * 
     */
    public Output<String> mediaAssetId() {
        return this.mediaAssetId;
    }

    private GetMediaAssetDistributionChannelAttachmentArgs() {}

    private GetMediaAssetDistributionChannelAttachmentArgs(GetMediaAssetDistributionChannelAttachmentArgs $) {
        this.distributionChannelId = $.distributionChannelId;
        this.mediaAssetId = $.mediaAssetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMediaAssetDistributionChannelAttachmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMediaAssetDistributionChannelAttachmentArgs $;

        public Builder() {
            $ = new GetMediaAssetDistributionChannelAttachmentArgs();
        }

        public Builder(GetMediaAssetDistributionChannelAttachmentArgs defaults) {
            $ = new GetMediaAssetDistributionChannelAttachmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param distributionChannelId Unique DistributionChannel identifier.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(Output<String> distributionChannelId) {
            $.distributionChannelId = distributionChannelId;
            return this;
        }

        /**
         * @param distributionChannelId Unique DistributionChannel identifier.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(String distributionChannelId) {
            return distributionChannelId(Output.of(distributionChannelId));
        }

        /**
         * @param mediaAssetId Unique MediaAsset identifier
         * 
         * @return builder
         * 
         */
        public Builder mediaAssetId(Output<String> mediaAssetId) {
            $.mediaAssetId = mediaAssetId;
            return this;
        }

        /**
         * @param mediaAssetId Unique MediaAsset identifier
         * 
         * @return builder
         * 
         */
        public Builder mediaAssetId(String mediaAssetId) {
            return mediaAssetId(Output.of(mediaAssetId));
        }

        public GetMediaAssetDistributionChannelAttachmentArgs build() {
            $.distributionChannelId = Objects.requireNonNull($.distributionChannelId, "expected parameter 'distributionChannelId' to be non-null");
            $.mediaAssetId = Objects.requireNonNull($.mediaAssetId, "expected parameter 'mediaAssetId' to be non-null");
            return $;
        }
    }

}