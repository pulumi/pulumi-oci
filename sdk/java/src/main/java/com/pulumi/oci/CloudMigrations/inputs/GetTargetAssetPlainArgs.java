// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetTargetAssetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTargetAssetPlainArgs Empty = new GetTargetAssetPlainArgs();

    /**
     * Unique target asset identifier
     * 
     */
    @Import(name="targetAssetId", required=true)
    private String targetAssetId;

    /**
     * @return Unique target asset identifier
     * 
     */
    public String targetAssetId() {
        return this.targetAssetId;
    }

    private GetTargetAssetPlainArgs() {}

    private GetTargetAssetPlainArgs(GetTargetAssetPlainArgs $) {
        this.targetAssetId = $.targetAssetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTargetAssetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTargetAssetPlainArgs $;

        public Builder() {
            $ = new GetTargetAssetPlainArgs();
        }

        public Builder(GetTargetAssetPlainArgs defaults) {
            $ = new GetTargetAssetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param targetAssetId Unique target asset identifier
         * 
         * @return builder
         * 
         */
        public Builder targetAssetId(String targetAssetId) {
            $.targetAssetId = targetAssetId;
            return this;
        }

        public GetTargetAssetPlainArgs build() {
            $.targetAssetId = Objects.requireNonNull($.targetAssetId, "expected parameter 'targetAssetId' to be non-null");
            return $;
        }
    }

}