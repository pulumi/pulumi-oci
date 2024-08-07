// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Blockchain.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBlockchainPlatformArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBlockchainPlatformArgs Empty = new GetBlockchainPlatformArgs();

    /**
     * Unique service identifier.
     * 
     */
    @Import(name="blockchainPlatformId", required=true)
    private Output<String> blockchainPlatformId;

    /**
     * @return Unique service identifier.
     * 
     */
    public Output<String> blockchainPlatformId() {
        return this.blockchainPlatformId;
    }

    private GetBlockchainPlatformArgs() {}

    private GetBlockchainPlatformArgs(GetBlockchainPlatformArgs $) {
        this.blockchainPlatformId = $.blockchainPlatformId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBlockchainPlatformArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBlockchainPlatformArgs $;

        public Builder() {
            $ = new GetBlockchainPlatformArgs();
        }

        public Builder(GetBlockchainPlatformArgs defaults) {
            $ = new GetBlockchainPlatformArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param blockchainPlatformId Unique service identifier.
         * 
         * @return builder
         * 
         */
        public Builder blockchainPlatformId(Output<String> blockchainPlatformId) {
            $.blockchainPlatformId = blockchainPlatformId;
            return this;
        }

        /**
         * @param blockchainPlatformId Unique service identifier.
         * 
         * @return builder
         * 
         */
        public Builder blockchainPlatformId(String blockchainPlatformId) {
            return blockchainPlatformId(Output.of(blockchainPlatformId));
        }

        public GetBlockchainPlatformArgs build() {
            if ($.blockchainPlatformId == null) {
                throw new MissingRequiredPropertyException("GetBlockchainPlatformArgs", "blockchainPlatformId");
            }
            return $;
        }
    }

}
