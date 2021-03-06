// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig;
import com.pulumi.oci.Core.outputs.GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationInstanceDetailLaunchDetail {
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig> agentConfigs;
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig> availabilityConfigs;
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under.
     * 
     */
    private final String capacityReservationId;
    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    private final String compartmentId;
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail> createVnicDetails;
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
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    private final Map<String,Object> extendedMetadata;
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    private final String faultDomain;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return Optional mutable instance options. As a part of Instance Metadata Service Security Header, This allows user to disable the legacy imds endpoints.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption> instanceOptions;
    /**
     * @return This is an advanced option.
     * 
     */
    private final String ipxeScript;
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
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
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption> launchOptions;
    /**
     * @return Custom metadata key/value pairs that you provide, such as the SSH public key required to connect to the instance.
     * 
     */
    private final Map<String,Object> metadata;
    /**
     * @return The platform configuration requested for the instance.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig> platformConfigs;
    /**
     * @return Configuration options for preemptible instances.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig> preemptibleInstanceConfigs;
    /**
     * @return The preferred maintenance action for an instance. The default is LIVE_MIGRATE, if live migration is supported.
     * 
     */
    private final String preferredMaintenanceAction;
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    private final String shape;
    /**
     * @return The shape configuration requested for the instance.
     * 
     */
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig> shapeConfigs;
    private final List<GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail> sourceDetails;

    @CustomType.Constructor
    private GetInstanceConfigurationInstanceDetailLaunchDetail(
        @CustomType.Parameter("agentConfigs") List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig> agentConfigs,
        @CustomType.Parameter("availabilityConfigs") List<GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig> availabilityConfigs,
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("capacityReservationId") String capacityReservationId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("createVnicDetails") List<GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail> createVnicDetails,
        @CustomType.Parameter("dedicatedVmHostId") String dedicatedVmHostId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("extendedMetadata") Map<String,Object> extendedMetadata,
        @CustomType.Parameter("faultDomain") String faultDomain,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("instanceOptions") List<GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption> instanceOptions,
        @CustomType.Parameter("ipxeScript") String ipxeScript,
        @CustomType.Parameter("isPvEncryptionInTransitEnabled") Boolean isPvEncryptionInTransitEnabled,
        @CustomType.Parameter("launchMode") String launchMode,
        @CustomType.Parameter("launchOptions") List<GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption> launchOptions,
        @CustomType.Parameter("metadata") Map<String,Object> metadata,
        @CustomType.Parameter("platformConfigs") List<GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig> platformConfigs,
        @CustomType.Parameter("preemptibleInstanceConfigs") List<GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig> preemptibleInstanceConfigs,
        @CustomType.Parameter("preferredMaintenanceAction") String preferredMaintenanceAction,
        @CustomType.Parameter("shape") String shape,
        @CustomType.Parameter("shapeConfigs") List<GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig> shapeConfigs,
        @CustomType.Parameter("sourceDetails") List<GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail> sourceDetails) {
        this.agentConfigs = agentConfigs;
        this.availabilityConfigs = availabilityConfigs;
        this.availabilityDomain = availabilityDomain;
        this.capacityReservationId = capacityReservationId;
        this.compartmentId = compartmentId;
        this.createVnicDetails = createVnicDetails;
        this.dedicatedVmHostId = dedicatedVmHostId;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.extendedMetadata = extendedMetadata;
        this.faultDomain = faultDomain;
        this.freeformTags = freeformTags;
        this.instanceOptions = instanceOptions;
        this.ipxeScript = ipxeScript;
        this.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
        this.launchMode = launchMode;
        this.launchOptions = launchOptions;
        this.metadata = metadata;
        this.platformConfigs = platformConfigs;
        this.preemptibleInstanceConfigs = preemptibleInstanceConfigs;
        this.preferredMaintenanceAction = preferredMaintenanceAction;
        this.shape = shape;
        this.shapeConfigs = shapeConfigs;
        this.sourceDetails = sourceDetails;
    }

    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig> agentConfigs() {
        return this.agentConfigs;
    }
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig> availabilityConfigs() {
        return this.availabilityConfigs;
    }
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under.
     * 
     */
    public String capacityReservationId() {
        return this.capacityReservationId;
    }
    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail> createVnicDetails() {
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
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
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
     * @return Optional mutable instance options. As a part of Instance Metadata Service Security Header, This allows user to disable the legacy imds endpoints.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption> instanceOptions() {
        return this.instanceOptions;
    }
    /**
     * @return This is an advanced option.
     * 
     */
    public String ipxeScript() {
        return this.ipxeScript;
    }
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
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
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption> launchOptions() {
        return this.launchOptions;
    }
    /**
     * @return Custom metadata key/value pairs that you provide, such as the SSH public key required to connect to the instance.
     * 
     */
    public Map<String,Object> metadata() {
        return this.metadata;
    }
    /**
     * @return The platform configuration requested for the instance.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig> platformConfigs() {
        return this.platformConfigs;
    }
    /**
     * @return Configuration options for preemptible instances.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig> preemptibleInstanceConfigs() {
        return this.preemptibleInstanceConfigs;
    }
    /**
     * @return The preferred maintenance action for an instance. The default is LIVE_MIGRATE, if live migration is supported.
     * 
     */
    public String preferredMaintenanceAction() {
        return this.preferredMaintenanceAction;
    }
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The shape configuration requested for the instance.
     * 
     */
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig> shapeConfigs() {
        return this.shapeConfigs;
    }
    public List<GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail> sourceDetails() {
        return this.sourceDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationInstanceDetailLaunchDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig> agentConfigs;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig> availabilityConfigs;
        private String availabilityDomain;
        private String capacityReservationId;
        private String compartmentId;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail> createVnicDetails;
        private String dedicatedVmHostId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> extendedMetadata;
        private String faultDomain;
        private Map<String,Object> freeformTags;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption> instanceOptions;
        private String ipxeScript;
        private Boolean isPvEncryptionInTransitEnabled;
        private String launchMode;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption> launchOptions;
        private Map<String,Object> metadata;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig> platformConfigs;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig> preemptibleInstanceConfigs;
        private String preferredMaintenanceAction;
        private String shape;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig> shapeConfigs;
        private List<GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail> sourceDetails;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInstanceConfigurationInstanceDetailLaunchDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentConfigs = defaults.agentConfigs;
    	      this.availabilityConfigs = defaults.availabilityConfigs;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.createVnicDetails = defaults.createVnicDetails;
    	      this.dedicatedVmHostId = defaults.dedicatedVmHostId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.extendedMetadata = defaults.extendedMetadata;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.instanceOptions = defaults.instanceOptions;
    	      this.ipxeScript = defaults.ipxeScript;
    	      this.isPvEncryptionInTransitEnabled = defaults.isPvEncryptionInTransitEnabled;
    	      this.launchMode = defaults.launchMode;
    	      this.launchOptions = defaults.launchOptions;
    	      this.metadata = defaults.metadata;
    	      this.platformConfigs = defaults.platformConfigs;
    	      this.preemptibleInstanceConfigs = defaults.preemptibleInstanceConfigs;
    	      this.preferredMaintenanceAction = defaults.preferredMaintenanceAction;
    	      this.shape = defaults.shape;
    	      this.shapeConfigs = defaults.shapeConfigs;
    	      this.sourceDetails = defaults.sourceDetails;
        }

        public Builder agentConfigs(List<GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig> agentConfigs) {
            this.agentConfigs = Objects.requireNonNull(agentConfigs);
            return this;
        }
        public Builder agentConfigs(GetInstanceConfigurationInstanceDetailLaunchDetailAgentConfig... agentConfigs) {
            return agentConfigs(List.of(agentConfigs));
        }
        public Builder availabilityConfigs(List<GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig> availabilityConfigs) {
            this.availabilityConfigs = Objects.requireNonNull(availabilityConfigs);
            return this;
        }
        public Builder availabilityConfigs(GetInstanceConfigurationInstanceDetailLaunchDetailAvailabilityConfig... availabilityConfigs) {
            return availabilityConfigs(List.of(availabilityConfigs));
        }
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
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
        public Builder createVnicDetails(List<GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail> createVnicDetails) {
            this.createVnicDetails = Objects.requireNonNull(createVnicDetails);
            return this;
        }
        public Builder createVnicDetails(GetInstanceConfigurationInstanceDetailLaunchDetailCreateVnicDetail... createVnicDetails) {
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
        public Builder instanceOptions(List<GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption> instanceOptions) {
            this.instanceOptions = Objects.requireNonNull(instanceOptions);
            return this;
        }
        public Builder instanceOptions(GetInstanceConfigurationInstanceDetailLaunchDetailInstanceOption... instanceOptions) {
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
        public Builder launchOptions(List<GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption> launchOptions) {
            this.launchOptions = Objects.requireNonNull(launchOptions);
            return this;
        }
        public Builder launchOptions(GetInstanceConfigurationInstanceDetailLaunchDetailLaunchOption... launchOptions) {
            return launchOptions(List.of(launchOptions));
        }
        public Builder metadata(Map<String,Object> metadata) {
            this.metadata = Objects.requireNonNull(metadata);
            return this;
        }
        public Builder platformConfigs(List<GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig> platformConfigs) {
            this.platformConfigs = Objects.requireNonNull(platformConfigs);
            return this;
        }
        public Builder platformConfigs(GetInstanceConfigurationInstanceDetailLaunchDetailPlatformConfig... platformConfigs) {
            return platformConfigs(List.of(platformConfigs));
        }
        public Builder preemptibleInstanceConfigs(List<GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig> preemptibleInstanceConfigs) {
            this.preemptibleInstanceConfigs = Objects.requireNonNull(preemptibleInstanceConfigs);
            return this;
        }
        public Builder preemptibleInstanceConfigs(GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfig... preemptibleInstanceConfigs) {
            return preemptibleInstanceConfigs(List.of(preemptibleInstanceConfigs));
        }
        public Builder preferredMaintenanceAction(String preferredMaintenanceAction) {
            this.preferredMaintenanceAction = Objects.requireNonNull(preferredMaintenanceAction);
            return this;
        }
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        public Builder shapeConfigs(List<GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig> shapeConfigs) {
            this.shapeConfigs = Objects.requireNonNull(shapeConfigs);
            return this;
        }
        public Builder shapeConfigs(GetInstanceConfigurationInstanceDetailLaunchDetailShapeConfig... shapeConfigs) {
            return shapeConfigs(List.of(shapeConfigs));
        }
        public Builder sourceDetails(List<GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail> sourceDetails) {
            this.sourceDetails = Objects.requireNonNull(sourceDetails);
            return this;
        }
        public Builder sourceDetails(GetInstanceConfigurationInstanceDetailLaunchDetailSourceDetail... sourceDetails) {
            return sourceDetails(List.of(sourceDetails));
        }        public GetInstanceConfigurationInstanceDetailLaunchDetail build() {
            return new GetInstanceConfigurationInstanceDetailLaunchDetail(agentConfigs, availabilityConfigs, availabilityDomain, capacityReservationId, compartmentId, createVnicDetails, dedicatedVmHostId, definedTags, displayName, extendedMetadata, faultDomain, freeformTags, instanceOptions, ipxeScript, isPvEncryptionInTransitEnabled, launchMode, launchOptions, metadata, platformConfigs, preemptibleInstanceConfigs, preferredMaintenanceAction, shape, shapeConfigs, sourceDetails);
        }
    }
}
