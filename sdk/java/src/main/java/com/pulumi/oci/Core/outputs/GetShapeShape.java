// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetShapeShapeMaxVnicAttachmentOption;
import com.pulumi.oci.Core.outputs.GetShapeShapeMemoryOption;
import com.pulumi.oci.Core.outputs.GetShapeShapeNetworkingBandwidthOption;
import com.pulumi.oci.Core.outputs.GetShapeShapeOcpuOption;
import com.pulumi.oci.Core.outputs.GetShapeShapePlatformConfigOption;
import com.pulumi.oci.Core.outputs.GetShapeShapeRecommendedAlternative;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetShapeShape {
    private List<String> baselineOcpuUtilizations;
    private String billingType;
    private String gpuDescription;
    private Integer gpus;
    private Boolean isBilledForStoppedInstance;
    private Boolean isFlexible;
    private Boolean isLiveMigrationSupported;
    private Boolean isSubcore;
    private String localDiskDescription;
    private Integer localDisks;
    private Double localDisksTotalSizeInGbs;
    private List<GetShapeShapeMaxVnicAttachmentOption> maxVnicAttachmentOptions;
    private Integer maxVnicAttachments;
    private Double memoryInGbs;
    private List<GetShapeShapeMemoryOption> memoryOptions;
    private Double minTotalBaselineOcpusRequired;
    private String name;
    private Integer networkPorts;
    private Double networkingBandwidthInGbps;
    private List<GetShapeShapeNetworkingBandwidthOption> networkingBandwidthOptions;
    private List<GetShapeShapeOcpuOption> ocpuOptions;
    private Double ocpus;
    private List<GetShapeShapePlatformConfigOption> platformConfigOptions;
    private String processorDescription;
    private List<String> quotaNames;
    private Integer rdmaBandwidthInGbps;
    private Integer rdmaPorts;
    private List<GetShapeShapeRecommendedAlternative> recommendedAlternatives;
    private List<String> resizeCompatibleShapes;

    private GetShapeShape() {}
    public List<String> baselineOcpuUtilizations() {
        return this.baselineOcpuUtilizations;
    }
    public String billingType() {
        return this.billingType;
    }
    public String gpuDescription() {
        return this.gpuDescription;
    }
    public Integer gpus() {
        return this.gpus;
    }
    public Boolean isBilledForStoppedInstance() {
        return this.isBilledForStoppedInstance;
    }
    public Boolean isFlexible() {
        return this.isFlexible;
    }
    public Boolean isLiveMigrationSupported() {
        return this.isLiveMigrationSupported;
    }
    public Boolean isSubcore() {
        return this.isSubcore;
    }
    public String localDiskDescription() {
        return this.localDiskDescription;
    }
    public Integer localDisks() {
        return this.localDisks;
    }
    public Double localDisksTotalSizeInGbs() {
        return this.localDisksTotalSizeInGbs;
    }
    public List<GetShapeShapeMaxVnicAttachmentOption> maxVnicAttachmentOptions() {
        return this.maxVnicAttachmentOptions;
    }
    public Integer maxVnicAttachments() {
        return this.maxVnicAttachments;
    }
    public Double memoryInGbs() {
        return this.memoryInGbs;
    }
    public List<GetShapeShapeMemoryOption> memoryOptions() {
        return this.memoryOptions;
    }
    public Double minTotalBaselineOcpusRequired() {
        return this.minTotalBaselineOcpusRequired;
    }
    public String name() {
        return this.name;
    }
    public Integer networkPorts() {
        return this.networkPorts;
    }
    public Double networkingBandwidthInGbps() {
        return this.networkingBandwidthInGbps;
    }
    public List<GetShapeShapeNetworkingBandwidthOption> networkingBandwidthOptions() {
        return this.networkingBandwidthOptions;
    }
    public List<GetShapeShapeOcpuOption> ocpuOptions() {
        return this.ocpuOptions;
    }
    public Double ocpus() {
        return this.ocpus;
    }
    public List<GetShapeShapePlatformConfigOption> platformConfigOptions() {
        return this.platformConfigOptions;
    }
    public String processorDescription() {
        return this.processorDescription;
    }
    public List<String> quotaNames() {
        return this.quotaNames;
    }
    public Integer rdmaBandwidthInGbps() {
        return this.rdmaBandwidthInGbps;
    }
    public Integer rdmaPorts() {
        return this.rdmaPorts;
    }
    public List<GetShapeShapeRecommendedAlternative> recommendedAlternatives() {
        return this.recommendedAlternatives;
    }
    public List<String> resizeCompatibleShapes() {
        return this.resizeCompatibleShapes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapeShape defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> baselineOcpuUtilizations;
        private String billingType;
        private String gpuDescription;
        private Integer gpus;
        private Boolean isBilledForStoppedInstance;
        private Boolean isFlexible;
        private Boolean isLiveMigrationSupported;
        private Boolean isSubcore;
        private String localDiskDescription;
        private Integer localDisks;
        private Double localDisksTotalSizeInGbs;
        private List<GetShapeShapeMaxVnicAttachmentOption> maxVnicAttachmentOptions;
        private Integer maxVnicAttachments;
        private Double memoryInGbs;
        private List<GetShapeShapeMemoryOption> memoryOptions;
        private Double minTotalBaselineOcpusRequired;
        private String name;
        private Integer networkPorts;
        private Double networkingBandwidthInGbps;
        private List<GetShapeShapeNetworkingBandwidthOption> networkingBandwidthOptions;
        private List<GetShapeShapeOcpuOption> ocpuOptions;
        private Double ocpus;
        private List<GetShapeShapePlatformConfigOption> platformConfigOptions;
        private String processorDescription;
        private List<String> quotaNames;
        private Integer rdmaBandwidthInGbps;
        private Integer rdmaPorts;
        private List<GetShapeShapeRecommendedAlternative> recommendedAlternatives;
        private List<String> resizeCompatibleShapes;
        public Builder() {}
        public Builder(GetShapeShape defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.baselineOcpuUtilizations = defaults.baselineOcpuUtilizations;
    	      this.billingType = defaults.billingType;
    	      this.gpuDescription = defaults.gpuDescription;
    	      this.gpus = defaults.gpus;
    	      this.isBilledForStoppedInstance = defaults.isBilledForStoppedInstance;
    	      this.isFlexible = defaults.isFlexible;
    	      this.isLiveMigrationSupported = defaults.isLiveMigrationSupported;
    	      this.isSubcore = defaults.isSubcore;
    	      this.localDiskDescription = defaults.localDiskDescription;
    	      this.localDisks = defaults.localDisks;
    	      this.localDisksTotalSizeInGbs = defaults.localDisksTotalSizeInGbs;
    	      this.maxVnicAttachmentOptions = defaults.maxVnicAttachmentOptions;
    	      this.maxVnicAttachments = defaults.maxVnicAttachments;
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.memoryOptions = defaults.memoryOptions;
    	      this.minTotalBaselineOcpusRequired = defaults.minTotalBaselineOcpusRequired;
    	      this.name = defaults.name;
    	      this.networkPorts = defaults.networkPorts;
    	      this.networkingBandwidthInGbps = defaults.networkingBandwidthInGbps;
    	      this.networkingBandwidthOptions = defaults.networkingBandwidthOptions;
    	      this.ocpuOptions = defaults.ocpuOptions;
    	      this.ocpus = defaults.ocpus;
    	      this.platformConfigOptions = defaults.platformConfigOptions;
    	      this.processorDescription = defaults.processorDescription;
    	      this.quotaNames = defaults.quotaNames;
    	      this.rdmaBandwidthInGbps = defaults.rdmaBandwidthInGbps;
    	      this.rdmaPorts = defaults.rdmaPorts;
    	      this.recommendedAlternatives = defaults.recommendedAlternatives;
    	      this.resizeCompatibleShapes = defaults.resizeCompatibleShapes;
        }

        @CustomType.Setter
        public Builder baselineOcpuUtilizations(List<String> baselineOcpuUtilizations) {
            this.baselineOcpuUtilizations = Objects.requireNonNull(baselineOcpuUtilizations);
            return this;
        }
        public Builder baselineOcpuUtilizations(String... baselineOcpuUtilizations) {
            return baselineOcpuUtilizations(List.of(baselineOcpuUtilizations));
        }
        @CustomType.Setter
        public Builder billingType(String billingType) {
            this.billingType = Objects.requireNonNull(billingType);
            return this;
        }
        @CustomType.Setter
        public Builder gpuDescription(String gpuDescription) {
            this.gpuDescription = Objects.requireNonNull(gpuDescription);
            return this;
        }
        @CustomType.Setter
        public Builder gpus(Integer gpus) {
            this.gpus = Objects.requireNonNull(gpus);
            return this;
        }
        @CustomType.Setter
        public Builder isBilledForStoppedInstance(Boolean isBilledForStoppedInstance) {
            this.isBilledForStoppedInstance = Objects.requireNonNull(isBilledForStoppedInstance);
            return this;
        }
        @CustomType.Setter
        public Builder isFlexible(Boolean isFlexible) {
            this.isFlexible = Objects.requireNonNull(isFlexible);
            return this;
        }
        @CustomType.Setter
        public Builder isLiveMigrationSupported(Boolean isLiveMigrationSupported) {
            this.isLiveMigrationSupported = Objects.requireNonNull(isLiveMigrationSupported);
            return this;
        }
        @CustomType.Setter
        public Builder isSubcore(Boolean isSubcore) {
            this.isSubcore = Objects.requireNonNull(isSubcore);
            return this;
        }
        @CustomType.Setter
        public Builder localDiskDescription(String localDiskDescription) {
            this.localDiskDescription = Objects.requireNonNull(localDiskDescription);
            return this;
        }
        @CustomType.Setter
        public Builder localDisks(Integer localDisks) {
            this.localDisks = Objects.requireNonNull(localDisks);
            return this;
        }
        @CustomType.Setter
        public Builder localDisksTotalSizeInGbs(Double localDisksTotalSizeInGbs) {
            this.localDisksTotalSizeInGbs = Objects.requireNonNull(localDisksTotalSizeInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder maxVnicAttachmentOptions(List<GetShapeShapeMaxVnicAttachmentOption> maxVnicAttachmentOptions) {
            this.maxVnicAttachmentOptions = Objects.requireNonNull(maxVnicAttachmentOptions);
            return this;
        }
        public Builder maxVnicAttachmentOptions(GetShapeShapeMaxVnicAttachmentOption... maxVnicAttachmentOptions) {
            return maxVnicAttachmentOptions(List.of(maxVnicAttachmentOptions));
        }
        @CustomType.Setter
        public Builder maxVnicAttachments(Integer maxVnicAttachments) {
            this.maxVnicAttachments = Objects.requireNonNull(maxVnicAttachments);
            return this;
        }
        @CustomType.Setter
        public Builder memoryInGbs(Double memoryInGbs) {
            this.memoryInGbs = Objects.requireNonNull(memoryInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder memoryOptions(List<GetShapeShapeMemoryOption> memoryOptions) {
            this.memoryOptions = Objects.requireNonNull(memoryOptions);
            return this;
        }
        public Builder memoryOptions(GetShapeShapeMemoryOption... memoryOptions) {
            return memoryOptions(List.of(memoryOptions));
        }
        @CustomType.Setter
        public Builder minTotalBaselineOcpusRequired(Double minTotalBaselineOcpusRequired) {
            this.minTotalBaselineOcpusRequired = Objects.requireNonNull(minTotalBaselineOcpusRequired);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder networkPorts(Integer networkPorts) {
            this.networkPorts = Objects.requireNonNull(networkPorts);
            return this;
        }
        @CustomType.Setter
        public Builder networkingBandwidthInGbps(Double networkingBandwidthInGbps) {
            this.networkingBandwidthInGbps = Objects.requireNonNull(networkingBandwidthInGbps);
            return this;
        }
        @CustomType.Setter
        public Builder networkingBandwidthOptions(List<GetShapeShapeNetworkingBandwidthOption> networkingBandwidthOptions) {
            this.networkingBandwidthOptions = Objects.requireNonNull(networkingBandwidthOptions);
            return this;
        }
        public Builder networkingBandwidthOptions(GetShapeShapeNetworkingBandwidthOption... networkingBandwidthOptions) {
            return networkingBandwidthOptions(List.of(networkingBandwidthOptions));
        }
        @CustomType.Setter
        public Builder ocpuOptions(List<GetShapeShapeOcpuOption> ocpuOptions) {
            this.ocpuOptions = Objects.requireNonNull(ocpuOptions);
            return this;
        }
        public Builder ocpuOptions(GetShapeShapeOcpuOption... ocpuOptions) {
            return ocpuOptions(List.of(ocpuOptions));
        }
        @CustomType.Setter
        public Builder ocpus(Double ocpus) {
            this.ocpus = Objects.requireNonNull(ocpus);
            return this;
        }
        @CustomType.Setter
        public Builder platformConfigOptions(List<GetShapeShapePlatformConfigOption> platformConfigOptions) {
            this.platformConfigOptions = Objects.requireNonNull(platformConfigOptions);
            return this;
        }
        public Builder platformConfigOptions(GetShapeShapePlatformConfigOption... platformConfigOptions) {
            return platformConfigOptions(List.of(platformConfigOptions));
        }
        @CustomType.Setter
        public Builder processorDescription(String processorDescription) {
            this.processorDescription = Objects.requireNonNull(processorDescription);
            return this;
        }
        @CustomType.Setter
        public Builder quotaNames(List<String> quotaNames) {
            this.quotaNames = Objects.requireNonNull(quotaNames);
            return this;
        }
        public Builder quotaNames(String... quotaNames) {
            return quotaNames(List.of(quotaNames));
        }
        @CustomType.Setter
        public Builder rdmaBandwidthInGbps(Integer rdmaBandwidthInGbps) {
            this.rdmaBandwidthInGbps = Objects.requireNonNull(rdmaBandwidthInGbps);
            return this;
        }
        @CustomType.Setter
        public Builder rdmaPorts(Integer rdmaPorts) {
            this.rdmaPorts = Objects.requireNonNull(rdmaPorts);
            return this;
        }
        @CustomType.Setter
        public Builder recommendedAlternatives(List<GetShapeShapeRecommendedAlternative> recommendedAlternatives) {
            this.recommendedAlternatives = Objects.requireNonNull(recommendedAlternatives);
            return this;
        }
        public Builder recommendedAlternatives(GetShapeShapeRecommendedAlternative... recommendedAlternatives) {
            return recommendedAlternatives(List.of(recommendedAlternatives));
        }
        @CustomType.Setter
        public Builder resizeCompatibleShapes(List<String> resizeCompatibleShapes) {
            this.resizeCompatibleShapes = Objects.requireNonNull(resizeCompatibleShapes);
            return this;
        }
        public Builder resizeCompatibleShapes(String... resizeCompatibleShapes) {
            return resizeCompatibleShapes(List.of(resizeCompatibleShapes));
        }
        public GetShapeShape build() {
            final var o = new GetShapeShape();
            o.baselineOcpuUtilizations = baselineOcpuUtilizations;
            o.billingType = billingType;
            o.gpuDescription = gpuDescription;
            o.gpus = gpus;
            o.isBilledForStoppedInstance = isBilledForStoppedInstance;
            o.isFlexible = isFlexible;
            o.isLiveMigrationSupported = isLiveMigrationSupported;
            o.isSubcore = isSubcore;
            o.localDiskDescription = localDiskDescription;
            o.localDisks = localDisks;
            o.localDisksTotalSizeInGbs = localDisksTotalSizeInGbs;
            o.maxVnicAttachmentOptions = maxVnicAttachmentOptions;
            o.maxVnicAttachments = maxVnicAttachments;
            o.memoryInGbs = memoryInGbs;
            o.memoryOptions = memoryOptions;
            o.minTotalBaselineOcpusRequired = minTotalBaselineOcpusRequired;
            o.name = name;
            o.networkPorts = networkPorts;
            o.networkingBandwidthInGbps = networkingBandwidthInGbps;
            o.networkingBandwidthOptions = networkingBandwidthOptions;
            o.ocpuOptions = ocpuOptions;
            o.ocpus = ocpus;
            o.platformConfigOptions = platformConfigOptions;
            o.processorDescription = processorDescription;
            o.quotaNames = quotaNames;
            o.rdmaBandwidthInGbps = rdmaBandwidthInGbps;
            o.rdmaPorts = rdmaPorts;
            o.recommendedAlternatives = recommendedAlternatives;
            o.resizeCompatibleShapes = resizeCompatibleShapes;
            return o;
        }
    }
}