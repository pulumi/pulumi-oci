// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAssetSourcePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAssetSourcePlainArgs Empty = new GetAssetSourcePlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
     * 
     */
    @Import(name="assetSourceId", required=true)
    private String assetSourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
     * 
     */
    public String assetSourceId() {
        return this.assetSourceId;
    }

    private GetAssetSourcePlainArgs() {}

    private GetAssetSourcePlainArgs(GetAssetSourcePlainArgs $) {
        this.assetSourceId = $.assetSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAssetSourcePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAssetSourcePlainArgs $;

        public Builder() {
            $ = new GetAssetSourcePlainArgs();
        }

        public Builder(GetAssetSourcePlainArgs defaults) {
            $ = new GetAssetSourcePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assetSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
         * 
         * @return builder
         * 
         */
        public Builder assetSourceId(String assetSourceId) {
            $.assetSourceId = assetSourceId;
            return this;
        }

        public GetAssetSourcePlainArgs build() {
            $.assetSourceId = Objects.requireNonNull($.assetSourceId, "expected parameter 'assetSourceId' to be non-null");
            return $;
        }
    }

}