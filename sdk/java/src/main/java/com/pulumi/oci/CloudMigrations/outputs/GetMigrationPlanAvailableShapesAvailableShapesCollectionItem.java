// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetMigrationPlanAvailableShapesAvailableShapesCollectionItem {
    /**
     * @return The availability domain in which to list resources.
     * 
     */
    private String availabilityDomain;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Description of the GPUs.
     * 
     */
    private String gpuDescription;
    /**
     * @return Number of GPUs.
     * 
     */
    private Integer gpus;
    /**
     * @return Description of local disks.
     * 
     */
    private String localDiskDescription;
    /**
     * @return Number of local disks.
     * 
     */
    private Integer localDisks;
    /**
     * @return Total size of local disks for shape.
     * 
     */
    private Double localDisksTotalSizeInGbs;
    /**
     * @return Maximum number of virtual network interfaces that can be attached.
     * 
     */
    private Integer maxVnicAttachments;
    /**
     * @return Amount of memory for the shape.
     * 
     */
    private Double memoryInGbs;
    /**
     * @return Minimum CPUs required.
     * 
     */
    private Double minTotalBaselineOcpusRequired;
    /**
     * @return Shape bandwidth.
     * 
     */
    private Double networkingBandwidthInGbps;
    /**
     * @return Number of CPUs.
     * 
     */
    private Double ocpus;
    /**
     * @return Shape name and availability domain.  Used for pagination.
     * 
     */
    private String paginationToken;
    /**
     * @return Description of the processor.
     * 
     */
    private String processorDescription;
    /**
     * @return Name of the shape.
     * 
     */
    private String shape;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;

    private GetMigrationPlanAvailableShapesAvailableShapesCollectionItem() {}
    /**
     * @return The availability domain in which to list resources.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Description of the GPUs.
     * 
     */
    public String gpuDescription() {
        return this.gpuDescription;
    }
    /**
     * @return Number of GPUs.
     * 
     */
    public Integer gpus() {
        return this.gpus;
    }
    /**
     * @return Description of local disks.
     * 
     */
    public String localDiskDescription() {
        return this.localDiskDescription;
    }
    /**
     * @return Number of local disks.
     * 
     */
    public Integer localDisks() {
        return this.localDisks;
    }
    /**
     * @return Total size of local disks for shape.
     * 
     */
    public Double localDisksTotalSizeInGbs() {
        return this.localDisksTotalSizeInGbs;
    }
    /**
     * @return Maximum number of virtual network interfaces that can be attached.
     * 
     */
    public Integer maxVnicAttachments() {
        return this.maxVnicAttachments;
    }
    /**
     * @return Amount of memory for the shape.
     * 
     */
    public Double memoryInGbs() {
        return this.memoryInGbs;
    }
    /**
     * @return Minimum CPUs required.
     * 
     */
    public Double minTotalBaselineOcpusRequired() {
        return this.minTotalBaselineOcpusRequired;
    }
    /**
     * @return Shape bandwidth.
     * 
     */
    public Double networkingBandwidthInGbps() {
        return this.networkingBandwidthInGbps;
    }
    /**
     * @return Number of CPUs.
     * 
     */
    public Double ocpus() {
        return this.ocpus;
    }
    /**
     * @return Shape name and availability domain.  Used for pagination.
     * 
     */
    public String paginationToken() {
        return this.paginationToken;
    }
    /**
     * @return Description of the processor.
     * 
     */
    public String processorDescription() {
        return this.processorDescription;
    }
    /**
     * @return Name of the shape.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationPlanAvailableShapesAvailableShapesCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private String gpuDescription;
        private Integer gpus;
        private String localDiskDescription;
        private Integer localDisks;
        private Double localDisksTotalSizeInGbs;
        private Integer maxVnicAttachments;
        private Double memoryInGbs;
        private Double minTotalBaselineOcpusRequired;
        private Double networkingBandwidthInGbps;
        private Double ocpus;
        private String paginationToken;
        private String processorDescription;
        private String shape;
        private Map<String,Object> systemTags;
        public Builder() {}
        public Builder(GetMigrationPlanAvailableShapesAvailableShapesCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.gpuDescription = defaults.gpuDescription;
    	      this.gpus = defaults.gpus;
    	      this.localDiskDescription = defaults.localDiskDescription;
    	      this.localDisks = defaults.localDisks;
    	      this.localDisksTotalSizeInGbs = defaults.localDisksTotalSizeInGbs;
    	      this.maxVnicAttachments = defaults.maxVnicAttachments;
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.minTotalBaselineOcpusRequired = defaults.minTotalBaselineOcpusRequired;
    	      this.networkingBandwidthInGbps = defaults.networkingBandwidthInGbps;
    	      this.ocpus = defaults.ocpus;
    	      this.paginationToken = defaults.paginationToken;
    	      this.processorDescription = defaults.processorDescription;
    	      this.shape = defaults.shape;
    	      this.systemTags = defaults.systemTags;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
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
        public Builder minTotalBaselineOcpusRequired(Double minTotalBaselineOcpusRequired) {
            this.minTotalBaselineOcpusRequired = Objects.requireNonNull(minTotalBaselineOcpusRequired);
            return this;
        }
        @CustomType.Setter
        public Builder networkingBandwidthInGbps(Double networkingBandwidthInGbps) {
            this.networkingBandwidthInGbps = Objects.requireNonNull(networkingBandwidthInGbps);
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(Double ocpus) {
            this.ocpus = Objects.requireNonNull(ocpus);
            return this;
        }
        @CustomType.Setter
        public Builder paginationToken(String paginationToken) {
            this.paginationToken = Objects.requireNonNull(paginationToken);
            return this;
        }
        @CustomType.Setter
        public Builder processorDescription(String processorDescription) {
            this.processorDescription = Objects.requireNonNull(processorDescription);
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public GetMigrationPlanAvailableShapesAvailableShapesCollectionItem build() {
            final var o = new GetMigrationPlanAvailableShapesAvailableShapesCollectionItem();
            o.availabilityDomain = availabilityDomain;
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.gpuDescription = gpuDescription;
            o.gpus = gpus;
            o.localDiskDescription = localDiskDescription;
            o.localDisks = localDisks;
            o.localDisksTotalSizeInGbs = localDisksTotalSizeInGbs;
            o.maxVnicAttachments = maxVnicAttachments;
            o.memoryInGbs = memoryInGbs;
            o.minTotalBaselineOcpusRequired = minTotalBaselineOcpusRequired;
            o.networkingBandwidthInGbps = networkingBandwidthInGbps;
            o.ocpus = ocpus;
            o.paginationToken = paginationToken;
            o.processorDescription = processorDescription;
            o.shape = shape;
            o.systemTags = systemTags;
            return o;
        }
    }
}