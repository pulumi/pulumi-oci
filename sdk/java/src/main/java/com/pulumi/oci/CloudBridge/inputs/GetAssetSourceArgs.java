// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAssetSourceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAssetSourceArgs Empty = new GetAssetSourceArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
     * 
     */
    @Import(name="assetSourceId", required=true)
    private Output<String> assetSourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
     * 
     */
    public Output<String> assetSourceId() {
        return this.assetSourceId;
    }

    private GetAssetSourceArgs() {}

    private GetAssetSourceArgs(GetAssetSourceArgs $) {
        this.assetSourceId = $.assetSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAssetSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAssetSourceArgs $;

        public Builder() {
            $ = new GetAssetSourceArgs();
        }

        public Builder(GetAssetSourceArgs defaults) {
            $ = new GetAssetSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assetSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
         * 
         * @return builder
         * 
         */
        public Builder assetSourceId(Output<String> assetSourceId) {
            $.assetSourceId = assetSourceId;
            return this;
        }

        /**
         * @param assetSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
         * 
         * @return builder
         * 
         */
        public Builder assetSourceId(String assetSourceId) {
            return assetSourceId(Output.of(assetSourceId));
        }

        public GetAssetSourceArgs build() {
            $.assetSourceId = Objects.requireNonNull($.assetSourceId, "expected parameter 'assetSourceId' to be non-null");
            return $;
        }
    }

}