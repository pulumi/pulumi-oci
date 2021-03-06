// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Blockchain.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs extends com.pulumi.resources.ResourceArgs {

    public static final BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs Empty = new BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs();

    /**
     * Number of OCPU allocation
     * 
     */
    @Import(name="ocpuAllocationNumber")
    private @Nullable Output<Double> ocpuAllocationNumber;

    /**
     * @return Number of OCPU allocation
     * 
     */
    public Optional<Output<Double>> ocpuAllocationNumber() {
        return Optional.ofNullable(this.ocpuAllocationNumber);
    }

    private BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs() {}

    private BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs(BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs $) {
        this.ocpuAllocationNumber = $.ocpuAllocationNumber;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs $;

        public Builder() {
            $ = new BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs();
        }

        public Builder(BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs defaults) {
            $ = new BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ocpuAllocationNumber Number of OCPU allocation
         * 
         * @return builder
         * 
         */
        public Builder ocpuAllocationNumber(@Nullable Output<Double> ocpuAllocationNumber) {
            $.ocpuAllocationNumber = ocpuAllocationNumber;
            return this;
        }

        /**
         * @param ocpuAllocationNumber Number of OCPU allocation
         * 
         * @return builder
         * 
         */
        public Builder ocpuAllocationNumber(Double ocpuAllocationNumber) {
            return ocpuAllocationNumber(Output.of(ocpuAllocationNumber));
        }

        public BlockchainPlatformComponentDetailOsnOcpuAllocationParamArgs build() {
            return $;
        }
    }

}
