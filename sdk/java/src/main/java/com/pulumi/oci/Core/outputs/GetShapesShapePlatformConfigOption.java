// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionAccessControlServiceOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionInputOutputMemoryManagementUnitOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionMeasuredBootOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionNumaNodesPerSocketPlatformOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionPercentageOfCoresEnabledOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionSecureBootOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionSymmetricMultiThreadingOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionTrustedPlatformModuleOption;
import com.pulumi.oci.Core.outputs.GetShapesShapePlatformConfigOptionVirtualInstructionsOption;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetShapesShapePlatformConfigOption {
    /**
     * @return Configuration options for the Access Control Service.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionAccessControlServiceOption> accessControlServiceOptions;
    /**
     * @return Configuration options for the input-output memory management unit.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionInputOutputMemoryManagementUnitOption> inputOutputMemoryManagementUnitOptions;
    /**
     * @return Configuration options for the Measured Boot feature.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionMeasuredBootOption> measuredBootOptions;
    /**
     * @return Configuration options for NUMA nodes per socket.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionNumaNodesPerSocketPlatformOption> numaNodesPerSocketPlatformOptions;
    /**
     * @return Configuration options for the percentage of cores enabled.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionPercentageOfCoresEnabledOption> percentageOfCoresEnabledOptions;
    /**
     * @return Configuration options for Secure Boot.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionSecureBootOption> secureBootOptions;
    /**
     * @return Configuration options for symmetric multi-threading.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionSymmetricMultiThreadingOption> symmetricMultiThreadingOptions;
    /**
     * @return Configuration options for the Trusted Platform Module (TPM).
     * 
     */
    private List<GetShapesShapePlatformConfigOptionTrustedPlatformModuleOption> trustedPlatformModuleOptions;
    /**
     * @return The type of platform being configured. (Supported types=[INTEL_VM, AMD_MILAN_BM, AMD_ROME_BM, AMD_ROME_BM_GPU, INTEL_ICELAKE_BM, INTEL_SKYLAKE_BM])
     * 
     */
    private String type;
    /**
     * @return Configuration options for the virtualization instructions.
     * 
     */
    private List<GetShapesShapePlatformConfigOptionVirtualInstructionsOption> virtualInstructionsOptions;

    private GetShapesShapePlatformConfigOption() {}
    /**
     * @return Configuration options for the Access Control Service.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionAccessControlServiceOption> accessControlServiceOptions() {
        return this.accessControlServiceOptions;
    }
    /**
     * @return Configuration options for the input-output memory management unit.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionInputOutputMemoryManagementUnitOption> inputOutputMemoryManagementUnitOptions() {
        return this.inputOutputMemoryManagementUnitOptions;
    }
    /**
     * @return Configuration options for the Measured Boot feature.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionMeasuredBootOption> measuredBootOptions() {
        return this.measuredBootOptions;
    }
    /**
     * @return Configuration options for NUMA nodes per socket.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionNumaNodesPerSocketPlatformOption> numaNodesPerSocketPlatformOptions() {
        return this.numaNodesPerSocketPlatformOptions;
    }
    /**
     * @return Configuration options for the percentage of cores enabled.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionPercentageOfCoresEnabledOption> percentageOfCoresEnabledOptions() {
        return this.percentageOfCoresEnabledOptions;
    }
    /**
     * @return Configuration options for Secure Boot.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionSecureBootOption> secureBootOptions() {
        return this.secureBootOptions;
    }
    /**
     * @return Configuration options for symmetric multi-threading.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionSymmetricMultiThreadingOption> symmetricMultiThreadingOptions() {
        return this.symmetricMultiThreadingOptions;
    }
    /**
     * @return Configuration options for the Trusted Platform Module (TPM).
     * 
     */
    public List<GetShapesShapePlatformConfigOptionTrustedPlatformModuleOption> trustedPlatformModuleOptions() {
        return this.trustedPlatformModuleOptions;
    }
    /**
     * @return The type of platform being configured. (Supported types=[INTEL_VM, AMD_MILAN_BM, AMD_ROME_BM, AMD_ROME_BM_GPU, INTEL_ICELAKE_BM, INTEL_SKYLAKE_BM])
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Configuration options for the virtualization instructions.
     * 
     */
    public List<GetShapesShapePlatformConfigOptionVirtualInstructionsOption> virtualInstructionsOptions() {
        return this.virtualInstructionsOptions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapesShapePlatformConfigOption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetShapesShapePlatformConfigOptionAccessControlServiceOption> accessControlServiceOptions;
        private List<GetShapesShapePlatformConfigOptionInputOutputMemoryManagementUnitOption> inputOutputMemoryManagementUnitOptions;
        private List<GetShapesShapePlatformConfigOptionMeasuredBootOption> measuredBootOptions;
        private List<GetShapesShapePlatformConfigOptionNumaNodesPerSocketPlatformOption> numaNodesPerSocketPlatformOptions;
        private List<GetShapesShapePlatformConfigOptionPercentageOfCoresEnabledOption> percentageOfCoresEnabledOptions;
        private List<GetShapesShapePlatformConfigOptionSecureBootOption> secureBootOptions;
        private List<GetShapesShapePlatformConfigOptionSymmetricMultiThreadingOption> symmetricMultiThreadingOptions;
        private List<GetShapesShapePlatformConfigOptionTrustedPlatformModuleOption> trustedPlatformModuleOptions;
        private String type;
        private List<GetShapesShapePlatformConfigOptionVirtualInstructionsOption> virtualInstructionsOptions;
        public Builder() {}
        public Builder(GetShapesShapePlatformConfigOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessControlServiceOptions = defaults.accessControlServiceOptions;
    	      this.inputOutputMemoryManagementUnitOptions = defaults.inputOutputMemoryManagementUnitOptions;
    	      this.measuredBootOptions = defaults.measuredBootOptions;
    	      this.numaNodesPerSocketPlatformOptions = defaults.numaNodesPerSocketPlatformOptions;
    	      this.percentageOfCoresEnabledOptions = defaults.percentageOfCoresEnabledOptions;
    	      this.secureBootOptions = defaults.secureBootOptions;
    	      this.symmetricMultiThreadingOptions = defaults.symmetricMultiThreadingOptions;
    	      this.trustedPlatformModuleOptions = defaults.trustedPlatformModuleOptions;
    	      this.type = defaults.type;
    	      this.virtualInstructionsOptions = defaults.virtualInstructionsOptions;
        }

        @CustomType.Setter
        public Builder accessControlServiceOptions(List<GetShapesShapePlatformConfigOptionAccessControlServiceOption> accessControlServiceOptions) {
            this.accessControlServiceOptions = Objects.requireNonNull(accessControlServiceOptions);
            return this;
        }
        public Builder accessControlServiceOptions(GetShapesShapePlatformConfigOptionAccessControlServiceOption... accessControlServiceOptions) {
            return accessControlServiceOptions(List.of(accessControlServiceOptions));
        }
        @CustomType.Setter
        public Builder inputOutputMemoryManagementUnitOptions(List<GetShapesShapePlatformConfigOptionInputOutputMemoryManagementUnitOption> inputOutputMemoryManagementUnitOptions) {
            this.inputOutputMemoryManagementUnitOptions = Objects.requireNonNull(inputOutputMemoryManagementUnitOptions);
            return this;
        }
        public Builder inputOutputMemoryManagementUnitOptions(GetShapesShapePlatformConfigOptionInputOutputMemoryManagementUnitOption... inputOutputMemoryManagementUnitOptions) {
            return inputOutputMemoryManagementUnitOptions(List.of(inputOutputMemoryManagementUnitOptions));
        }
        @CustomType.Setter
        public Builder measuredBootOptions(List<GetShapesShapePlatformConfigOptionMeasuredBootOption> measuredBootOptions) {
            this.measuredBootOptions = Objects.requireNonNull(measuredBootOptions);
            return this;
        }
        public Builder measuredBootOptions(GetShapesShapePlatformConfigOptionMeasuredBootOption... measuredBootOptions) {
            return measuredBootOptions(List.of(measuredBootOptions));
        }
        @CustomType.Setter
        public Builder numaNodesPerSocketPlatformOptions(List<GetShapesShapePlatformConfigOptionNumaNodesPerSocketPlatformOption> numaNodesPerSocketPlatformOptions) {
            this.numaNodesPerSocketPlatformOptions = Objects.requireNonNull(numaNodesPerSocketPlatformOptions);
            return this;
        }
        public Builder numaNodesPerSocketPlatformOptions(GetShapesShapePlatformConfigOptionNumaNodesPerSocketPlatformOption... numaNodesPerSocketPlatformOptions) {
            return numaNodesPerSocketPlatformOptions(List.of(numaNodesPerSocketPlatformOptions));
        }
        @CustomType.Setter
        public Builder percentageOfCoresEnabledOptions(List<GetShapesShapePlatformConfigOptionPercentageOfCoresEnabledOption> percentageOfCoresEnabledOptions) {
            this.percentageOfCoresEnabledOptions = Objects.requireNonNull(percentageOfCoresEnabledOptions);
            return this;
        }
        public Builder percentageOfCoresEnabledOptions(GetShapesShapePlatformConfigOptionPercentageOfCoresEnabledOption... percentageOfCoresEnabledOptions) {
            return percentageOfCoresEnabledOptions(List.of(percentageOfCoresEnabledOptions));
        }
        @CustomType.Setter
        public Builder secureBootOptions(List<GetShapesShapePlatformConfigOptionSecureBootOption> secureBootOptions) {
            this.secureBootOptions = Objects.requireNonNull(secureBootOptions);
            return this;
        }
        public Builder secureBootOptions(GetShapesShapePlatformConfigOptionSecureBootOption... secureBootOptions) {
            return secureBootOptions(List.of(secureBootOptions));
        }
        @CustomType.Setter
        public Builder symmetricMultiThreadingOptions(List<GetShapesShapePlatformConfigOptionSymmetricMultiThreadingOption> symmetricMultiThreadingOptions) {
            this.symmetricMultiThreadingOptions = Objects.requireNonNull(symmetricMultiThreadingOptions);
            return this;
        }
        public Builder symmetricMultiThreadingOptions(GetShapesShapePlatformConfigOptionSymmetricMultiThreadingOption... symmetricMultiThreadingOptions) {
            return symmetricMultiThreadingOptions(List.of(symmetricMultiThreadingOptions));
        }
        @CustomType.Setter
        public Builder trustedPlatformModuleOptions(List<GetShapesShapePlatformConfigOptionTrustedPlatformModuleOption> trustedPlatformModuleOptions) {
            this.trustedPlatformModuleOptions = Objects.requireNonNull(trustedPlatformModuleOptions);
            return this;
        }
        public Builder trustedPlatformModuleOptions(GetShapesShapePlatformConfigOptionTrustedPlatformModuleOption... trustedPlatformModuleOptions) {
            return trustedPlatformModuleOptions(List.of(trustedPlatformModuleOptions));
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder virtualInstructionsOptions(List<GetShapesShapePlatformConfigOptionVirtualInstructionsOption> virtualInstructionsOptions) {
            this.virtualInstructionsOptions = Objects.requireNonNull(virtualInstructionsOptions);
            return this;
        }
        public Builder virtualInstructionsOptions(GetShapesShapePlatformConfigOptionVirtualInstructionsOption... virtualInstructionsOptions) {
            return virtualInstructionsOptions(List.of(virtualInstructionsOptions));
        }
        public GetShapesShapePlatformConfigOption build() {
            final var o = new GetShapesShapePlatformConfigOption();
            o.accessControlServiceOptions = accessControlServiceOptions;
            o.inputOutputMemoryManagementUnitOptions = inputOutputMemoryManagementUnitOptions;
            o.measuredBootOptions = measuredBootOptions;
            o.numaNodesPerSocketPlatformOptions = numaNodesPerSocketPlatformOptions;
            o.percentageOfCoresEnabledOptions = percentageOfCoresEnabledOptions;
            o.secureBootOptions = secureBootOptions;
            o.symmetricMultiThreadingOptions = symmetricMultiThreadingOptions;
            o.trustedPlatformModuleOptions = trustedPlatformModuleOptions;
            o.type = type;
            o.virtualInstructionsOptions = virtualInstructionsOptions;
            return o;
        }
    }
}