// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceAgentConfig;
import com.pulumi.oci.Core.outputs.GetInstanceAvailabilityConfig;
import com.pulumi.oci.Core.outputs.GetInstanceCreateVnicDetail;
import com.pulumi.oci.Core.outputs.GetInstanceInstanceOption;
import com.pulumi.oci.Core.outputs.GetInstanceLaunchOption;
import com.pulumi.oci.Core.outputs.GetInstancePlatformConfig;
import com.pulumi.oci.Core.outputs.GetInstancePreemptibleInstanceConfig;
import com.pulumi.oci.Core.outputs.GetInstanceShapeConfig;
import com.pulumi.oci.Core.outputs.GetInstanceSourceDetail;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInstanceResult {
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    private List<GetInstanceAgentConfig> agentConfigs;
    private Boolean async;
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    private List<GetInstanceAvailabilityConfig> availabilityConfigs;
    /**
     * @return The availability domain the instance is running in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The OCID of the attached boot volume. If the `source_type` is `bootVolume`, this will be the same OCID as the `source_id`.
     * 
     */
    private String bootVolumeId;
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under. When this field contains an empty string or is null, the instance is not currently in a capacity reservation. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    private String capacityReservationId;
    /**
     * @return The OCID of the compartment that contains the instance.
     * 
     */
    private String compartmentId;
    private List<GetInstanceCreateVnicDetail> createVnicDetails;
    /**
     * @return The OCID of dedicated VM host.
     * 
     */
    private String dedicatedVmHostId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    private Map<String,Object> extendedMetadata;
    /**
     * @return The name of the fault domain the instance is running in.
     * 
     */
    private String faultDomain;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The hostname for the instance VNIC&#39;s primary private IP.
     * 
     * @deprecated
     * The &#39;hostname_label&#39; field has been deprecated. Please use &#39;hostname_label under create_vnic_details&#39; instead.
     * 
     */
    @Deprecated /* The 'hostname_label' field has been deprecated. Please use 'hostname_label under create_vnic_details' instead. */
    private String hostnameLabel;
    /**
     * @return The OCID of the instance.
     * 
     */
    private String id;
    /**
     * @return Deprecated. Use `sourceDetails` instead.
     * 
     * @deprecated
     * The &#39;image&#39; field has been deprecated. Please use &#39;source_details&#39; instead. If both fields are specified, then &#39;source_details&#39; will be used.
     * 
     */
    @Deprecated /* The 'image' field has been deprecated. Please use 'source_details' instead. If both fields are specified, then 'source_details' will be used. */
    private String image;
    private String instanceId;
    /**
     * @return Optional mutable instance options
     * 
     */
    private List<GetInstanceInstanceOption> instanceOptions;
    /**
     * @return When a bare metal or virtual machine instance boots, the iPXE firmware that runs on the instance is configured to run an iPXE script to continue the boot process.
     * 
     */
    private String ipxeScript;
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/LaunchInstanceDetails).
     * 
     */
    private Boolean isPvEncryptionInTransitEnabled;
    /**
     * @return Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * 
     */
    private String launchMode;
    /**
     * @return Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     * 
     */
    private List<GetInstanceLaunchOption> launchOptions;
    /**
     * @return Custom metadata that you provide.
     * 
     */
    private Map<String,Object> metadata;
    /**
     * @return The platform configuration for the instance.
     * 
     */
    private List<GetInstancePlatformConfig> platformConfigs;
    /**
     * @return (Optional) Configuration options for preemptible instances.
     * 
     */
    private List<GetInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs;
    /**
     * @return (Optional) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     * 
     */
    private Boolean preserveBootVolume;
    /**
     * @return The private IP address of instance VNIC. To set the private IP address, use the `private_ip` argument in create_vnic_details.
     * 
     */
    private String privateIp;
    /**
     * @return The public IP address of instance VNIC (if enabled).
     * 
     */
    private String publicIp;
    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    private String region;
    /**
     * @return The shape of the instance. The shape determines the number of CPUs and the amount of memory allocated to the instance. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
     * 
     */
    private String shape;
    /**
     * @return The shape configuration for an instance. The shape configuration determines the resources allocated to an instance.
     * 
     */
    private List<GetInstanceShapeConfig> shapeConfigs;
    private List<GetInstanceSourceDetail> sourceDetails;
    /**
     * @return The current state of the instance.
     * 
     */
    private String state;
    /**
     * @deprecated
     * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnet_id under create_vnic_details&#39; instead.
     * 
     */
    @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnet_id under create_vnic_details' instead. */
    private String subnetId;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The date and time the instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the instance is expected to be stopped / started,  in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). After that time if instance hasn&#39;t been rebooted, Oracle will reboot the instance within 24 hours of the due time. Regardless of how the instance was stopped, the flag will be reset to empty as soon as instance reaches Stopped state. Example: `2018-05-25T21:10:29.600Z`
     * 
     */
    private String timeMaintenanceRebootDue;

    private GetInstanceResult() {}
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    public List<GetInstanceAgentConfig> agentConfigs() {
        return this.agentConfigs;
    }
    public Boolean async() {
        return this.async;
    }
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    public List<GetInstanceAvailabilityConfig> availabilityConfigs() {
        return this.availabilityConfigs;
    }
    /**
     * @return The availability domain the instance is running in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The OCID of the attached boot volume. If the `source_type` is `bootVolume`, this will be the same OCID as the `source_id`.
     * 
     */
    public String bootVolumeId() {
        return this.bootVolumeId;
    }
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under. When this field contains an empty string or is null, the instance is not currently in a capacity reservation. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The OCID of the compartment that contains the instance.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetInstanceCreateVnicDetail> createVnicDetails() {
        return this.createVnicDetails;
    }
    /**
     * @return The OCID of dedicated VM host.
     * 
     */
    public String dedicatedVmHostId() {
        return this.dedicatedVmHostId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    public Map<String,Object> extendedMetadata() {
        return this.extendedMetadata;
    }
    /**
     * @return The name of the fault domain the instance is running in.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The hostname for the instance VNIC&#39;s primary private IP.
     * 
     * @deprecated
     * The &#39;hostname_label&#39; field has been deprecated. Please use &#39;hostname_label under create_vnic_details&#39; instead.
     * 
     */
    @Deprecated /* The 'hostname_label' field has been deprecated. Please use 'hostname_label under create_vnic_details' instead. */
    public String hostnameLabel() {
        return this.hostnameLabel;
    }
    /**
     * @return The OCID of the instance.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Deprecated. Use `sourceDetails` instead.
     * 
     * @deprecated
     * The &#39;image&#39; field has been deprecated. Please use &#39;source_details&#39; instead. If both fields are specified, then &#39;source_details&#39; will be used.
     * 
     */
    @Deprecated /* The 'image' field has been deprecated. Please use 'source_details' instead. If both fields are specified, then 'source_details' will be used. */
    public String image() {
        return this.image;
    }
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return Optional mutable instance options
     * 
     */
    public List<GetInstanceInstanceOption> instanceOptions() {
        return this.instanceOptions;
    }
    /**
     * @return When a bare metal or virtual machine instance boots, the iPXE firmware that runs on the instance is configured to run an iPXE script to continue the boot process.
     * 
     */
    public String ipxeScript() {
        return this.ipxeScript;
    }
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/LaunchInstanceDetails).
     * 
     */
    public Boolean isPvEncryptionInTransitEnabled() {
        return this.isPvEncryptionInTransitEnabled;
    }
    /**
     * @return Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * 
     */
    public String launchMode() {
        return this.launchMode;
    }
    /**
     * @return Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     * 
     */
    public List<GetInstanceLaunchOption> launchOptions() {
        return this.launchOptions;
    }
    /**
     * @return Custom metadata that you provide.
     * 
     */
    public Map<String,Object> metadata() {
        return this.metadata;
    }
    /**
     * @return The platform configuration for the instance.
     * 
     */
    public List<GetInstancePlatformConfig> platformConfigs() {
        return this.platformConfigs;
    }
    /**
     * @return (Optional) Configuration options for preemptible instances.
     * 
     */
    public List<GetInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs() {
        return this.preemptibleInstanceConfigs;
    }
    /**
     * @return (Optional) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     * 
     */
    public Boolean preserveBootVolume() {
        return this.preserveBootVolume;
    }
    /**
     * @return The private IP address of instance VNIC. To set the private IP address, use the `private_ip` argument in create_vnic_details.
     * 
     */
    public String privateIp() {
        return this.privateIp;
    }
    /**
     * @return The public IP address of instance VNIC (if enabled).
     * 
     */
    public String publicIp() {
        return this.publicIp;
    }
    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    public String region() {
        return this.region;
    }
    /**
     * @return The shape of the instance. The shape determines the number of CPUs and the amount of memory allocated to the instance. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The shape configuration for an instance. The shape configuration determines the resources allocated to an instance.
     * 
     */
    public List<GetInstanceShapeConfig> shapeConfigs() {
        return this.shapeConfigs;
    }
    public List<GetInstanceSourceDetail> sourceDetails() {
        return this.sourceDetails;
    }
    /**
     * @return The current state of the instance.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @deprecated
     * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnet_id under create_vnic_details&#39; instead.
     * 
     */
    @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnet_id under create_vnic_details' instead. */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the instance is expected to be stopped / started,  in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). After that time if instance hasn&#39;t been rebooted, Oracle will reboot the instance within 24 hours of the due time. Regardless of how the instance was stopped, the flag will be reset to empty as soon as instance reaches Stopped state. Example: `2018-05-25T21:10:29.600Z`
     * 
     */
    public String timeMaintenanceRebootDue() {
        return this.timeMaintenanceRebootDue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstanceAgentConfig> agentConfigs;
        private Boolean async;
        private List<GetInstanceAvailabilityConfig> availabilityConfigs;
        private String availabilityDomain;
        private String bootVolumeId;
        private String capacityReservationId;
        private String compartmentId;
        private List<GetInstanceCreateVnicDetail> createVnicDetails;
        private String dedicatedVmHostId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> extendedMetadata;
        private String faultDomain;
        private Map<String,Object> freeformTags;
        private String hostnameLabel;
        private String id;
        private String image;
        private String instanceId;
        private List<GetInstanceInstanceOption> instanceOptions;
        private String ipxeScript;
        private Boolean isPvEncryptionInTransitEnabled;
        private String launchMode;
        private List<GetInstanceLaunchOption> launchOptions;
        private Map<String,Object> metadata;
        private List<GetInstancePlatformConfig> platformConfigs;
        private List<GetInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs;
        private Boolean preserveBootVolume;
        private String privateIp;
        private String publicIp;
        private String region;
        private String shape;
        private List<GetInstanceShapeConfig> shapeConfigs;
        private List<GetInstanceSourceDetail> sourceDetails;
        private String state;
        private String subnetId;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeMaintenanceRebootDue;
        public Builder() {}
        public Builder(GetInstanceResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentConfigs = defaults.agentConfigs;
    	      this.async = defaults.async;
    	      this.availabilityConfigs = defaults.availabilityConfigs;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.bootVolumeId = defaults.bootVolumeId;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.createVnicDetails = defaults.createVnicDetails;
    	      this.dedicatedVmHostId = defaults.dedicatedVmHostId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.extendedMetadata = defaults.extendedMetadata;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hostnameLabel = defaults.hostnameLabel;
    	      this.id = defaults.id;
    	      this.image = defaults.image;
    	      this.instanceId = defaults.instanceId;
    	      this.instanceOptions = defaults.instanceOptions;
    	      this.ipxeScript = defaults.ipxeScript;
    	      this.isPvEncryptionInTransitEnabled = defaults.isPvEncryptionInTransitEnabled;
    	      this.launchMode = defaults.launchMode;
    	      this.launchOptions = defaults.launchOptions;
    	      this.metadata = defaults.metadata;
    	      this.platformConfigs = defaults.platformConfigs;
    	      this.preemptibleInstanceConfigs = defaults.preemptibleInstanceConfigs;
    	      this.preserveBootVolume = defaults.preserveBootVolume;
    	      this.privateIp = defaults.privateIp;
    	      this.publicIp = defaults.publicIp;
    	      this.region = defaults.region;
    	      this.shape = defaults.shape;
    	      this.shapeConfigs = defaults.shapeConfigs;
    	      this.sourceDetails = defaults.sourceDetails;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeMaintenanceRebootDue = defaults.timeMaintenanceRebootDue;
        }

        @CustomType.Setter
        public Builder agentConfigs(List<GetInstanceAgentConfig> agentConfigs) {
            this.agentConfigs = Objects.requireNonNull(agentConfigs);
            return this;
        }
        public Builder agentConfigs(GetInstanceAgentConfig... agentConfigs) {
            return agentConfigs(List.of(agentConfigs));
        }
        @CustomType.Setter
        public Builder async(Boolean async) {
            this.async = Objects.requireNonNull(async);
            return this;
        }
        @CustomType.Setter
        public Builder availabilityConfigs(List<GetInstanceAvailabilityConfig> availabilityConfigs) {
            this.availabilityConfigs = Objects.requireNonNull(availabilityConfigs);
            return this;
        }
        public Builder availabilityConfigs(GetInstanceAvailabilityConfig... availabilityConfigs) {
            return availabilityConfigs(List.of(availabilityConfigs));
        }
        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder bootVolumeId(String bootVolumeId) {
            this.bootVolumeId = Objects.requireNonNull(bootVolumeId);
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(String capacityReservationId) {
            this.capacityReservationId = Objects.requireNonNull(capacityReservationId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder createVnicDetails(List<GetInstanceCreateVnicDetail> createVnicDetails) {
            this.createVnicDetails = Objects.requireNonNull(createVnicDetails);
            return this;
        }
        public Builder createVnicDetails(GetInstanceCreateVnicDetail... createVnicDetails) {
            return createVnicDetails(List.of(createVnicDetails));
        }
        @CustomType.Setter
        public Builder dedicatedVmHostId(String dedicatedVmHostId) {
            this.dedicatedVmHostId = Objects.requireNonNull(dedicatedVmHostId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder extendedMetadata(Map<String,Object> extendedMetadata) {
            this.extendedMetadata = Objects.requireNonNull(extendedMetadata);
            return this;
        }
        @CustomType.Setter
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder hostnameLabel(String hostnameLabel) {
            this.hostnameLabel = Objects.requireNonNull(hostnameLabel);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder image(String image) {
            this.image = Objects.requireNonNull(image);
            return this;
        }
        @CustomType.Setter
        public Builder instanceId(String instanceId) {
            this.instanceId = Objects.requireNonNull(instanceId);
            return this;
        }
        @CustomType.Setter
        public Builder instanceOptions(List<GetInstanceInstanceOption> instanceOptions) {
            this.instanceOptions = Objects.requireNonNull(instanceOptions);
            return this;
        }
        public Builder instanceOptions(GetInstanceInstanceOption... instanceOptions) {
            return instanceOptions(List.of(instanceOptions));
        }
        @CustomType.Setter
        public Builder ipxeScript(String ipxeScript) {
            this.ipxeScript = Objects.requireNonNull(ipxeScript);
            return this;
        }
        @CustomType.Setter
        public Builder isPvEncryptionInTransitEnabled(Boolean isPvEncryptionInTransitEnabled) {
            this.isPvEncryptionInTransitEnabled = Objects.requireNonNull(isPvEncryptionInTransitEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder launchMode(String launchMode) {
            this.launchMode = Objects.requireNonNull(launchMode);
            return this;
        }
        @CustomType.Setter
        public Builder launchOptions(List<GetInstanceLaunchOption> launchOptions) {
            this.launchOptions = Objects.requireNonNull(launchOptions);
            return this;
        }
        public Builder launchOptions(GetInstanceLaunchOption... launchOptions) {
            return launchOptions(List.of(launchOptions));
        }
        @CustomType.Setter
        public Builder metadata(Map<String,Object> metadata) {
            this.metadata = Objects.requireNonNull(metadata);
            return this;
        }
        @CustomType.Setter
        public Builder platformConfigs(List<GetInstancePlatformConfig> platformConfigs) {
            this.platformConfigs = Objects.requireNonNull(platformConfigs);
            return this;
        }
        public Builder platformConfigs(GetInstancePlatformConfig... platformConfigs) {
            return platformConfigs(List.of(platformConfigs));
        }
        @CustomType.Setter
        public Builder preemptibleInstanceConfigs(List<GetInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs) {
            this.preemptibleInstanceConfigs = Objects.requireNonNull(preemptibleInstanceConfigs);
            return this;
        }
        public Builder preemptibleInstanceConfigs(GetInstancePreemptibleInstanceConfig... preemptibleInstanceConfigs) {
            return preemptibleInstanceConfigs(List.of(preemptibleInstanceConfigs));
        }
        @CustomType.Setter
        public Builder preserveBootVolume(Boolean preserveBootVolume) {
            this.preserveBootVolume = Objects.requireNonNull(preserveBootVolume);
            return this;
        }
        @CustomType.Setter
        public Builder privateIp(String privateIp) {
            this.privateIp = Objects.requireNonNull(privateIp);
            return this;
        }
        @CustomType.Setter
        public Builder publicIp(String publicIp) {
            this.publicIp = Objects.requireNonNull(publicIp);
            return this;
        }
        @CustomType.Setter
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        @CustomType.Setter
        public Builder shapeConfigs(List<GetInstanceShapeConfig> shapeConfigs) {
            this.shapeConfigs = Objects.requireNonNull(shapeConfigs);
            return this;
        }
        public Builder shapeConfigs(GetInstanceShapeConfig... shapeConfigs) {
            return shapeConfigs(List.of(shapeConfigs));
        }
        @CustomType.Setter
        public Builder sourceDetails(List<GetInstanceSourceDetail> sourceDetails) {
            this.sourceDetails = Objects.requireNonNull(sourceDetails);
            return this;
        }
        public Builder sourceDetails(GetInstanceSourceDetail... sourceDetails) {
            return sourceDetails(List.of(sourceDetails));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeMaintenanceRebootDue(String timeMaintenanceRebootDue) {
            this.timeMaintenanceRebootDue = Objects.requireNonNull(timeMaintenanceRebootDue);
            return this;
        }
        public GetInstanceResult build() {
            final var o = new GetInstanceResult();
            o.agentConfigs = agentConfigs;
            o.async = async;
            o.availabilityConfigs = availabilityConfigs;
            o.availabilityDomain = availabilityDomain;
            o.bootVolumeId = bootVolumeId;
            o.capacityReservationId = capacityReservationId;
            o.compartmentId = compartmentId;
            o.createVnicDetails = createVnicDetails;
            o.dedicatedVmHostId = dedicatedVmHostId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.extendedMetadata = extendedMetadata;
            o.faultDomain = faultDomain;
            o.freeformTags = freeformTags;
            o.hostnameLabel = hostnameLabel;
            o.id = id;
            o.image = image;
            o.instanceId = instanceId;
            o.instanceOptions = instanceOptions;
            o.ipxeScript = ipxeScript;
            o.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            o.launchMode = launchMode;
            o.launchOptions = launchOptions;
            o.metadata = metadata;
            o.platformConfigs = platformConfigs;
            o.preemptibleInstanceConfigs = preemptibleInstanceConfigs;
            o.preserveBootVolume = preserveBootVolume;
            o.privateIp = privateIp;
            o.publicIp = publicIp;
            o.region = region;
            o.shape = shape;
            o.shapeConfigs = shapeConfigs;
            o.sourceDetails = sourceDetails;
            o.state = state;
            o.subnetId = subnetId;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeMaintenanceRebootDue = timeMaintenanceRebootDue;
            return o;
        }
    }
}