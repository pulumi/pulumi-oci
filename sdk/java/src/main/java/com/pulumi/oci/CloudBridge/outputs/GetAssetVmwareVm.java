// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudBridge.outputs.GetAssetVmwareVmCustomerTag;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAssetVmwareVm {
    /**
     * @return Cluster name.
     * 
     */
    private String cluster;
    /**
     * @return Customer fields.
     * 
     */
    private List<String> customerFields;
    /**
     * @return Customer defined tags.
     * 
     */
    private List<GetAssetVmwareVmCustomerTag> customerTags;
    /**
     * @return Fault tolerance bandwidth.
     * 
     */
    private Integer faultToleranceBandwidth;
    /**
     * @return Fault tolerance to secondary latency.
     * 
     */
    private Integer faultToleranceSecondaryLatency;
    /**
     * @return Fault tolerance state.
     * 
     */
    private String faultToleranceState;
    /**
     * @return vCenter-specific identifier of the virtual machine.
     * 
     */
    private String instanceUuid;
    /**
     * @return Indicates that change tracking is supported for virtual disks of this virtual machine. However, even if change tracking is supported, it might not be available for all disks of the virtual machine.
     * 
     */
    private Boolean isDisksCbtEnabled;
    /**
     * @return Whether changed block tracking for this VM&#39;s disk is active.
     * 
     */
    private Boolean isDisksUuidEnabled;
    /**
     * @return Path directory of the asset.
     * 
     */
    private String path;
    /**
     * @return VMware tools status.
     * 
     */
    private String vmwareToolsStatus;

    private GetAssetVmwareVm() {}
    /**
     * @return Cluster name.
     * 
     */
    public String cluster() {
        return this.cluster;
    }
    /**
     * @return Customer fields.
     * 
     */
    public List<String> customerFields() {
        return this.customerFields;
    }
    /**
     * @return Customer defined tags.
     * 
     */
    public List<GetAssetVmwareVmCustomerTag> customerTags() {
        return this.customerTags;
    }
    /**
     * @return Fault tolerance bandwidth.
     * 
     */
    public Integer faultToleranceBandwidth() {
        return this.faultToleranceBandwidth;
    }
    /**
     * @return Fault tolerance to secondary latency.
     * 
     */
    public Integer faultToleranceSecondaryLatency() {
        return this.faultToleranceSecondaryLatency;
    }
    /**
     * @return Fault tolerance state.
     * 
     */
    public String faultToleranceState() {
        return this.faultToleranceState;
    }
    /**
     * @return vCenter-specific identifier of the virtual machine.
     * 
     */
    public String instanceUuid() {
        return this.instanceUuid;
    }
    /**
     * @return Indicates that change tracking is supported for virtual disks of this virtual machine. However, even if change tracking is supported, it might not be available for all disks of the virtual machine.
     * 
     */
    public Boolean isDisksCbtEnabled() {
        return this.isDisksCbtEnabled;
    }
    /**
     * @return Whether changed block tracking for this VM&#39;s disk is active.
     * 
     */
    public Boolean isDisksUuidEnabled() {
        return this.isDisksUuidEnabled;
    }
    /**
     * @return Path directory of the asset.
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return VMware tools status.
     * 
     */
    public String vmwareToolsStatus() {
        return this.vmwareToolsStatus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetVmwareVm defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String cluster;
        private List<String> customerFields;
        private List<GetAssetVmwareVmCustomerTag> customerTags;
        private Integer faultToleranceBandwidth;
        private Integer faultToleranceSecondaryLatency;
        private String faultToleranceState;
        private String instanceUuid;
        private Boolean isDisksCbtEnabled;
        private Boolean isDisksUuidEnabled;
        private String path;
        private String vmwareToolsStatus;
        public Builder() {}
        public Builder(GetAssetVmwareVm defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cluster = defaults.cluster;
    	      this.customerFields = defaults.customerFields;
    	      this.customerTags = defaults.customerTags;
    	      this.faultToleranceBandwidth = defaults.faultToleranceBandwidth;
    	      this.faultToleranceSecondaryLatency = defaults.faultToleranceSecondaryLatency;
    	      this.faultToleranceState = defaults.faultToleranceState;
    	      this.instanceUuid = defaults.instanceUuid;
    	      this.isDisksCbtEnabled = defaults.isDisksCbtEnabled;
    	      this.isDisksUuidEnabled = defaults.isDisksUuidEnabled;
    	      this.path = defaults.path;
    	      this.vmwareToolsStatus = defaults.vmwareToolsStatus;
        }

        @CustomType.Setter
        public Builder cluster(String cluster) {
            this.cluster = Objects.requireNonNull(cluster);
            return this;
        }
        @CustomType.Setter
        public Builder customerFields(List<String> customerFields) {
            this.customerFields = Objects.requireNonNull(customerFields);
            return this;
        }
        public Builder customerFields(String... customerFields) {
            return customerFields(List.of(customerFields));
        }
        @CustomType.Setter
        public Builder customerTags(List<GetAssetVmwareVmCustomerTag> customerTags) {
            this.customerTags = Objects.requireNonNull(customerTags);
            return this;
        }
        public Builder customerTags(GetAssetVmwareVmCustomerTag... customerTags) {
            return customerTags(List.of(customerTags));
        }
        @CustomType.Setter
        public Builder faultToleranceBandwidth(Integer faultToleranceBandwidth) {
            this.faultToleranceBandwidth = Objects.requireNonNull(faultToleranceBandwidth);
            return this;
        }
        @CustomType.Setter
        public Builder faultToleranceSecondaryLatency(Integer faultToleranceSecondaryLatency) {
            this.faultToleranceSecondaryLatency = Objects.requireNonNull(faultToleranceSecondaryLatency);
            return this;
        }
        @CustomType.Setter
        public Builder faultToleranceState(String faultToleranceState) {
            this.faultToleranceState = Objects.requireNonNull(faultToleranceState);
            return this;
        }
        @CustomType.Setter
        public Builder instanceUuid(String instanceUuid) {
            this.instanceUuid = Objects.requireNonNull(instanceUuid);
            return this;
        }
        @CustomType.Setter
        public Builder isDisksCbtEnabled(Boolean isDisksCbtEnabled) {
            this.isDisksCbtEnabled = Objects.requireNonNull(isDisksCbtEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder isDisksUuidEnabled(Boolean isDisksUuidEnabled) {
            this.isDisksUuidEnabled = Objects.requireNonNull(isDisksUuidEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            this.path = Objects.requireNonNull(path);
            return this;
        }
        @CustomType.Setter
        public Builder vmwareToolsStatus(String vmwareToolsStatus) {
            this.vmwareToolsStatus = Objects.requireNonNull(vmwareToolsStatus);
            return this;
        }
        public GetAssetVmwareVm build() {
            final var o = new GetAssetVmwareVm();
            o.cluster = cluster;
            o.customerFields = customerFields;
            o.customerTags = customerTags;
            o.faultToleranceBandwidth = faultToleranceBandwidth;
            o.faultToleranceSecondaryLatency = faultToleranceSecondaryLatency;
            o.faultToleranceState = faultToleranceState;
            o.instanceUuid = instanceUuid;
            o.isDisksCbtEnabled = isDisksCbtEnabled;
            o.isDisksUuidEnabled = isDisksUuidEnabled;
            o.path = path;
            o.vmwareToolsStatus = vmwareToolsStatus;
            return o;
        }
    }
}