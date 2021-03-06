// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceAgentConfig;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceAvailabilityConfig;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceCreateVnicDetail;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceInstanceOption;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceLaunchOption;
import com.pulumi.oci.Core.outputs.GetInstancesInstancePlatformConfig;
import com.pulumi.oci.Core.outputs.GetInstancesInstancePreemptibleInstanceConfig;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceShapeConfig;
import com.pulumi.oci.Core.outputs.GetInstancesInstanceSourceDetail;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInstancesInstance {
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    private final List<GetInstancesInstanceAgentConfig> agentConfigs;
    private final Boolean async;
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    private final List<GetInstancesInstanceAvailabilityConfig> availabilityConfigs;
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The OCID of the attached boot volume. If the `source_type` is `bootVolume`, this will be the same OCID as the `source_id`.
     * 
     */
    private final String bootVolumeId;
    /**
     * @return The OCID of the compute capacity reservation.
     * 
     */
    private final String capacityReservationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    private final List<GetInstancesInstanceCreateVnicDetail> createVnicDetails;
    /**
     * @return The OCID of dedicated VM host.
     * 
     */
    private final String dedicatedVmHostId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private final String displayName;
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    private final Map<String,Object> extendedMetadata;
    /**
     * @return The name of the fault domain the instance is running in.
     * 
     */
    private final String faultDomain;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @deprecated
     * The &#39;hostname_label&#39; field has been deprecated. Please use &#39;hostname_label under create_vnic_details&#39; instead.
     * 
     */
    @Deprecated /* The 'hostname_label' field has been deprecated. Please use 'hostname_label under create_vnic_details' instead. */
    private final String hostnameLabel;
    /**
     * @return The OCID of the instance.
     * 
     */
    private final String id;
    /**
     * @return Deprecated. Use `sourceDetails` instead.
     * 
     * @deprecated
     * The &#39;image&#39; field has been deprecated. Please use &#39;source_details&#39; instead. If both fields are specified, then &#39;source_details&#39; will be used.
     * 
     */
    @Deprecated /* The 'image' field has been deprecated. Please use 'source_details' instead. If both fields are specified, then 'source_details' will be used. */
    private final String image;
    /**
     * @return Optional mutable instance options
     * 
     */
    private final List<GetInstancesInstanceInstanceOption> instanceOptions;
    /**
     * @return When a bare metal or virtual machine instance boots, the iPXE firmware that runs on the instance is configured to run an iPXE script to continue the boot process.
     * 
     */
    private final String ipxeScript;
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/LaunchInstanceDetails).
     * 
     */
    private final Boolean isPvEncryptionInTransitEnabled;
    /**
     * @return Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * 
     */
    private final String launchMode;
    /**
     * @return Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     * 
     */
    private final List<GetInstancesInstanceLaunchOption> launchOptions;
    /**
     * @return Custom metadata that you provide.
     * 
     */
    private final Map<String,Object> metadata;
    /**
     * @return The platform configuration for the instance.
     * 
     */
    private final List<GetInstancesInstancePlatformConfig> platformConfigs;
    /**
     * @return (Optional) Configuration options for preemptible instances.
     * 
     */
    private final List<GetInstancesInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs;
    /**
     * @return (Optional) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     * 
     */
    private final Boolean preserveBootVolume;
    private final String privateIp;
    private final String publicIp;
    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    private final String region;
    /**
     * @return The shape of the instance. The shape determines the number of CPUs and the amount of memory allocated to the instance. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
     * 
     */
    private final String shape;
    /**
     * @return The shape configuration for an instance. The shape configuration determines the resources allocated to an instance.
     * 
     */
    private final List<GetInstancesInstanceShapeConfig> shapeConfigs;
    private final List<GetInstancesInstanceSourceDetail> sourceDetails;
    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    private final String state;
    /**
     * @deprecated
     * The &#39;subnet_id&#39; field has been deprecated. Please use &#39;subnet_id under create_vnic_details&#39; instead.
     * 
     */
    @Deprecated /* The 'subnet_id' field has been deprecated. Please use 'subnet_id under create_vnic_details' instead. */
    private final String subnetId;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> systemTags;
    /**
     * @return The date and time the instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the instance is expected to be stopped / started,  in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). After that time if instance hasn&#39;t been rebooted, Oracle will reboot the instance within 24 hours of the due time. Regardless of how the instance was stopped, the flag will be reset to empty as soon as instance reaches Stopped state. Example: `2018-05-25T21:10:29.600Z`
     * 
     */
    private final String timeMaintenanceRebootDue;

    @CustomType.Constructor
    private GetInstancesInstance(
        @CustomType.Parameter("agentConfigs") List<GetInstancesInstanceAgentConfig> agentConfigs,
        @CustomType.Parameter("async") Boolean async,
        @CustomType.Parameter("availabilityConfigs") List<GetInstancesInstanceAvailabilityConfig> availabilityConfigs,
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("bootVolumeId") String bootVolumeId,
        @CustomType.Parameter("capacityReservationId") String capacityReservationId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("createVnicDetails") List<GetInstancesInstanceCreateVnicDetail> createVnicDetails,
        @CustomType.Parameter("dedicatedVmHostId") String dedicatedVmHostId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("extendedMetadata") Map<String,Object> extendedMetadata,
        @CustomType.Parameter("faultDomain") String faultDomain,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("hostnameLabel") String hostnameLabel,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("image") String image,
        @CustomType.Parameter("instanceOptions") List<GetInstancesInstanceInstanceOption> instanceOptions,
        @CustomType.Parameter("ipxeScript") String ipxeScript,
        @CustomType.Parameter("isPvEncryptionInTransitEnabled") Boolean isPvEncryptionInTransitEnabled,
        @CustomType.Parameter("launchMode") String launchMode,
        @CustomType.Parameter("launchOptions") List<GetInstancesInstanceLaunchOption> launchOptions,
        @CustomType.Parameter("metadata") Map<String,Object> metadata,
        @CustomType.Parameter("platformConfigs") List<GetInstancesInstancePlatformConfig> platformConfigs,
        @CustomType.Parameter("preemptibleInstanceConfigs") List<GetInstancesInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs,
        @CustomType.Parameter("preserveBootVolume") Boolean preserveBootVolume,
        @CustomType.Parameter("privateIp") String privateIp,
        @CustomType.Parameter("publicIp") String publicIp,
        @CustomType.Parameter("region") String region,
        @CustomType.Parameter("shape") String shape,
        @CustomType.Parameter("shapeConfigs") List<GetInstancesInstanceShapeConfig> shapeConfigs,
        @CustomType.Parameter("sourceDetails") List<GetInstancesInstanceSourceDetail> sourceDetails,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("subnetId") String subnetId,
        @CustomType.Parameter("systemTags") Map<String,Object> systemTags,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeMaintenanceRebootDue") String timeMaintenanceRebootDue) {
        this.agentConfigs = agentConfigs;
        this.async = async;
        this.availabilityConfigs = availabilityConfigs;
        this.availabilityDomain = availabilityDomain;
        this.bootVolumeId = bootVolumeId;
        this.capacityReservationId = capacityReservationId;
        this.compartmentId = compartmentId;
        this.createVnicDetails = createVnicDetails;
        this.dedicatedVmHostId = dedicatedVmHostId;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.extendedMetadata = extendedMetadata;
        this.faultDomain = faultDomain;
        this.freeformTags = freeformTags;
        this.hostnameLabel = hostnameLabel;
        this.id = id;
        this.image = image;
        this.instanceOptions = instanceOptions;
        this.ipxeScript = ipxeScript;
        this.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
        this.launchMode = launchMode;
        this.launchOptions = launchOptions;
        this.metadata = metadata;
        this.platformConfigs = platformConfigs;
        this.preemptibleInstanceConfigs = preemptibleInstanceConfigs;
        this.preserveBootVolume = preserveBootVolume;
        this.privateIp = privateIp;
        this.publicIp = publicIp;
        this.region = region;
        this.shape = shape;
        this.shapeConfigs = shapeConfigs;
        this.sourceDetails = sourceDetails;
        this.state = state;
        this.subnetId = subnetId;
        this.systemTags = systemTags;
        this.timeCreated = timeCreated;
        this.timeMaintenanceRebootDue = timeMaintenanceRebootDue;
    }

    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    public List<GetInstancesInstanceAgentConfig> agentConfigs() {
        return this.agentConfigs;
    }
    public Boolean async() {
        return this.async;
    }
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    public List<GetInstancesInstanceAvailabilityConfig> availabilityConfigs() {
        return this.availabilityConfigs;
    }
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
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
     * @return The OCID of the compute capacity reservation.
     * 
     */
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetInstancesInstanceCreateVnicDetail> createVnicDetails() {
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
     * @return A filter to return only resources that match the given display name exactly.
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
    /**
     * @return Optional mutable instance options
     * 
     */
    public List<GetInstancesInstanceInstanceOption> instanceOptions() {
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
    public List<GetInstancesInstanceLaunchOption> launchOptions() {
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
    public List<GetInstancesInstancePlatformConfig> platformConfigs() {
        return this.platformConfigs;
    }
    /**
     * @return (Optional) Configuration options for preemptible instances.
     * 
     */
    public List<GetInstancesInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs() {
        return this.preemptibleInstanceConfigs;
    }
    /**
     * @return (Optional) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. Defaults to false if not specified.
     * 
     */
    public Boolean preserveBootVolume() {
        return this.preserveBootVolume;
    }
    public String privateIp() {
        return this.privateIp;
    }
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
    public List<GetInstancesInstanceShapeConfig> shapeConfigs() {
        return this.shapeConfigs;
    }
    public List<GetInstancesInstanceSourceDetail> sourceDetails() {
        return this.sourceDetails;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
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

    public static Builder builder(GetInstancesInstance defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetInstancesInstanceAgentConfig> agentConfigs;
        private Boolean async;
        private List<GetInstancesInstanceAvailabilityConfig> availabilityConfigs;
        private String availabilityDomain;
        private String bootVolumeId;
        private String capacityReservationId;
        private String compartmentId;
        private List<GetInstancesInstanceCreateVnicDetail> createVnicDetails;
        private String dedicatedVmHostId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> extendedMetadata;
        private String faultDomain;
        private Map<String,Object> freeformTags;
        private String hostnameLabel;
        private String id;
        private String image;
        private List<GetInstancesInstanceInstanceOption> instanceOptions;
        private String ipxeScript;
        private Boolean isPvEncryptionInTransitEnabled;
        private String launchMode;
        private List<GetInstancesInstanceLaunchOption> launchOptions;
        private Map<String,Object> metadata;
        private List<GetInstancesInstancePlatformConfig> platformConfigs;
        private List<GetInstancesInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs;
        private Boolean preserveBootVolume;
        private String privateIp;
        private String publicIp;
        private String region;
        private String shape;
        private List<GetInstancesInstanceShapeConfig> shapeConfigs;
        private List<GetInstancesInstanceSourceDetail> sourceDetails;
        private String state;
        private String subnetId;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeMaintenanceRebootDue;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstancesInstance defaults) {
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

        public Builder agentConfigs(List<GetInstancesInstanceAgentConfig> agentConfigs) {
            this.agentConfigs = Objects.requireNonNull(agentConfigs);
            return this;
        }
        public Builder agentConfigs(GetInstancesInstanceAgentConfig... agentConfigs) {
            return agentConfigs(List.of(agentConfigs));
        }
        public Builder async(Boolean async) {
            this.async = Objects.requireNonNull(async);
            return this;
        }
        public Builder availabilityConfigs(List<GetInstancesInstanceAvailabilityConfig> availabilityConfigs) {
            this.availabilityConfigs = Objects.requireNonNull(availabilityConfigs);
            return this;
        }
        public Builder availabilityConfigs(GetInstancesInstanceAvailabilityConfig... availabilityConfigs) {
            return availabilityConfigs(List.of(availabilityConfigs));
        }
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder bootVolumeId(String bootVolumeId) {
            this.bootVolumeId = Objects.requireNonNull(bootVolumeId);
            return this;
        }
        public Builder capacityReservationId(String capacityReservationId) {
            this.capacityReservationId = Objects.requireNonNull(capacityReservationId);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder createVnicDetails(List<GetInstancesInstanceCreateVnicDetail> createVnicDetails) {
            this.createVnicDetails = Objects.requireNonNull(createVnicDetails);
            return this;
        }
        public Builder createVnicDetails(GetInstancesInstanceCreateVnicDetail... createVnicDetails) {
            return createVnicDetails(List.of(createVnicDetails));
        }
        public Builder dedicatedVmHostId(String dedicatedVmHostId) {
            this.dedicatedVmHostId = Objects.requireNonNull(dedicatedVmHostId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder extendedMetadata(Map<String,Object> extendedMetadata) {
            this.extendedMetadata = Objects.requireNonNull(extendedMetadata);
            return this;
        }
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder hostnameLabel(String hostnameLabel) {
            this.hostnameLabel = Objects.requireNonNull(hostnameLabel);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder image(String image) {
            this.image = Objects.requireNonNull(image);
            return this;
        }
        public Builder instanceOptions(List<GetInstancesInstanceInstanceOption> instanceOptions) {
            this.instanceOptions = Objects.requireNonNull(instanceOptions);
            return this;
        }
        public Builder instanceOptions(GetInstancesInstanceInstanceOption... instanceOptions) {
            return instanceOptions(List.of(instanceOptions));
        }
        public Builder ipxeScript(String ipxeScript) {
            this.ipxeScript = Objects.requireNonNull(ipxeScript);
            return this;
        }
        public Builder isPvEncryptionInTransitEnabled(Boolean isPvEncryptionInTransitEnabled) {
            this.isPvEncryptionInTransitEnabled = Objects.requireNonNull(isPvEncryptionInTransitEnabled);
            return this;
        }
        public Builder launchMode(String launchMode) {
            this.launchMode = Objects.requireNonNull(launchMode);
            return this;
        }
        public Builder launchOptions(List<GetInstancesInstanceLaunchOption> launchOptions) {
            this.launchOptions = Objects.requireNonNull(launchOptions);
            return this;
        }
        public Builder launchOptions(GetInstancesInstanceLaunchOption... launchOptions) {
            return launchOptions(List.of(launchOptions));
        }
        public Builder metadata(Map<String,Object> metadata) {
            this.metadata = Objects.requireNonNull(metadata);
            return this;
        }
        public Builder platformConfigs(List<GetInstancesInstancePlatformConfig> platformConfigs) {
            this.platformConfigs = Objects.requireNonNull(platformConfigs);
            return this;
        }
        public Builder platformConfigs(GetInstancesInstancePlatformConfig... platformConfigs) {
            return platformConfigs(List.of(platformConfigs));
        }
        public Builder preemptibleInstanceConfigs(List<GetInstancesInstancePreemptibleInstanceConfig> preemptibleInstanceConfigs) {
            this.preemptibleInstanceConfigs = Objects.requireNonNull(preemptibleInstanceConfigs);
            return this;
        }
        public Builder preemptibleInstanceConfigs(GetInstancesInstancePreemptibleInstanceConfig... preemptibleInstanceConfigs) {
            return preemptibleInstanceConfigs(List.of(preemptibleInstanceConfigs));
        }
        public Builder preserveBootVolume(Boolean preserveBootVolume) {
            this.preserveBootVolume = Objects.requireNonNull(preserveBootVolume);
            return this;
        }
        public Builder privateIp(String privateIp) {
            this.privateIp = Objects.requireNonNull(privateIp);
            return this;
        }
        public Builder publicIp(String publicIp) {
            this.publicIp = Objects.requireNonNull(publicIp);
            return this;
        }
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        public Builder shapeConfigs(List<GetInstancesInstanceShapeConfig> shapeConfigs) {
            this.shapeConfigs = Objects.requireNonNull(shapeConfigs);
            return this;
        }
        public Builder shapeConfigs(GetInstancesInstanceShapeConfig... shapeConfigs) {
            return shapeConfigs(List.of(shapeConfigs));
        }
        public Builder sourceDetails(List<GetInstancesInstanceSourceDetail> sourceDetails) {
            this.sourceDetails = Objects.requireNonNull(sourceDetails);
            return this;
        }
        public Builder sourceDetails(GetInstancesInstanceSourceDetail... sourceDetails) {
            return sourceDetails(List.of(sourceDetails));
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeMaintenanceRebootDue(String timeMaintenanceRebootDue) {
            this.timeMaintenanceRebootDue = Objects.requireNonNull(timeMaintenanceRebootDue);
            return this;
        }        public GetInstancesInstance build() {
            return new GetInstancesInstance(agentConfigs, async, availabilityConfigs, availabilityDomain, bootVolumeId, capacityReservationId, compartmentId, createVnicDetails, dedicatedVmHostId, definedTags, displayName, extendedMetadata, faultDomain, freeformTags, hostnameLabel, id, image, instanceOptions, ipxeScript, isPvEncryptionInTransitEnabled, launchMode, launchOptions, metadata, platformConfigs, preemptibleInstanceConfigs, preserveBootVolume, privateIp, publicIp, region, shape, shapeConfigs, sourceDetails, state, subnetId, systemTags, timeCreated, timeMaintenanceRebootDue);
        }
    }
}
