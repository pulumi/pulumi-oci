// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Blockchain.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOsnArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOsnArgs Empty = new GetOsnArgs();

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

    /**
     * OSN identifier.
     * 
     */
    @Import(name="osnId", required=true)
    private Output<String> osnId;

    /**
     * @return OSN identifier.
     * 
     */
    public Output<String> osnId() {
        return this.osnId;
    }

    private GetOsnArgs() {}

    private GetOsnArgs(GetOsnArgs $) {
        this.blockchainPlatformId = $.blockchainPlatformId;
        this.osnId = $.osnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOsnArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOsnArgs $;

        public Builder() {
            $ = new GetOsnArgs();
        }

        public Builder(GetOsnArgs defaults) {
            $ = new GetOsnArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param osnId OSN identifier.
         * 
         * @return builder
         * 
         */
        public Builder osnId(Output<String> osnId) {
            $.osnId = osnId;
            return this;
        }

        /**
         * @param osnId OSN identifier.
         * 
         * @return builder
         * 
         */
        public Builder osnId(String osnId) {
            return osnId(Output.of(osnId));
        }

        public GetOsnArgs build() {
            if ($.blockchainPlatformId == null) {
                throw new MissingRequiredPropertyException("GetOsnArgs", "blockchainPlatformId");
            }
            if ($.osnId == null) {
                throw new MissingRequiredPropertyException("GetOsnArgs", "osnId");
            }
            return $;
        }
    }

}
