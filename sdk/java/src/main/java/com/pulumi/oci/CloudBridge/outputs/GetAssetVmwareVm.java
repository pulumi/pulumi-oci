// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
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
            if (cluster == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "cluster");
            }
            this.cluster = cluster;
            return this;
        }
        @CustomType.Setter
        public Builder customerFields(List<String> customerFields) {
            if (customerFields == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "customerFields");
            }
            this.customerFields = customerFields;
            return this;
        }
        public Builder customerFields(String... customerFields) {
            return customerFields(List.of(customerFields));
        }
        @CustomType.Setter
        public Builder customerTags(List<GetAssetVmwareVmCustomerTag> customerTags) {
            if (customerTags == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "customerTags");
            }
            this.customerTags = customerTags;
            return this;
        }
        public Builder customerTags(GetAssetVmwareVmCustomerTag... customerTags) {
            return customerTags(List.of(customerTags));
        }
        @CustomType.Setter
        public Builder faultToleranceBandwidth(Integer faultToleranceBandwidth) {
            if (faultToleranceBandwidth == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "faultToleranceBandwidth");
            }
            this.faultToleranceBandwidth = faultToleranceBandwidth;
            return this;
        }
        @CustomType.Setter
        public Builder faultToleranceSecondaryLatency(Integer faultToleranceSecondaryLatency) {
            if (faultToleranceSecondaryLatency == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "faultToleranceSecondaryLatency");
            }
            this.faultToleranceSecondaryLatency = faultToleranceSecondaryLatency;
            return this;
        }
        @CustomType.Setter
        public Builder faultToleranceState(String faultToleranceState) {
            if (faultToleranceState == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "faultToleranceState");
            }
            this.faultToleranceState = faultToleranceState;
            return this;
        }
        @CustomType.Setter
        public Builder instanceUuid(String instanceUuid) {
            if (instanceUuid == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "instanceUuid");
            }
            this.instanceUuid = instanceUuid;
            return this;
        }
        @CustomType.Setter
        public Builder isDisksCbtEnabled(Boolean isDisksCbtEnabled) {
            if (isDisksCbtEnabled == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "isDisksCbtEnabled");
            }
            this.isDisksCbtEnabled = isDisksCbtEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isDisksUuidEnabled(Boolean isDisksUuidEnabled) {
            if (isDisksUuidEnabled == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "isDisksUuidEnabled");
            }
            this.isDisksUuidEnabled = isDisksUuidEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder vmwareToolsStatus(String vmwareToolsStatus) {
            if (vmwareToolsStatus == null) {
              throw new MissingRequiredPropertyException("GetAssetVmwareVm", "vmwareToolsStatus");
            }
            this.vmwareToolsStatus = vmwareToolsStatus;
            return this;
        }
        public GetAssetVmwareVm build() {
            final var _resultValue = new GetAssetVmwareVm();
            _resultValue.cluster = cluster;
            _resultValue.customerFields = customerFields;
            _resultValue.customerTags = customerTags;
            _resultValue.faultToleranceBandwidth = faultToleranceBandwidth;
            _resultValue.faultToleranceSecondaryLatency = faultToleranceSecondaryLatency;
            _resultValue.faultToleranceState = faultToleranceState;
            _resultValue.instanceUuid = instanceUuid;
            _resultValue.isDisksCbtEnabled = isDisksCbtEnabled;
            _resultValue.isDisksUuidEnabled = isDisksUuidEnabled;
            _resultValue.path = path;
            _resultValue.vmwareToolsStatus = vmwareToolsStatus;
            return _resultValue;
        }
    }
}
