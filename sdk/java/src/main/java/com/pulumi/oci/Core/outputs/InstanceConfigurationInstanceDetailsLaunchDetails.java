// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfig;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetails;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptions;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptions;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfig;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig;
import com.pulumi.oci.Core.outputs.InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetails;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceConfigurationInstanceDetailsLaunchDetails {
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfig agentConfig;
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig availabilityConfig;
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under.
     * 
     */
    private @Nullable String capacityReservationId;
    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetails createVnicDetails;
    /**
     * @return The OCID of dedicated VM host.
     * 
     */
    private @Nullable String dedicatedVmHostId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private @Nullable Map<String,Object> definedTags;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    private @Nullable Map<String,Object> extendedMetadata;
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    private @Nullable String faultDomain;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private @Nullable Map<String,Object> freeformTags;
    /**
     * @return Optional mutable instance options. As a part of Instance Metadata Service Security Header, This allows user to disable the legacy imds endpoints.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptions instanceOptions;
    /**
     * @return This is an advanced option.
     * 
     */
    private @Nullable String ipxeScript;
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
     * 
     */
    private @Nullable Boolean isPvEncryptionInTransitEnabled;
    /**
     * @return Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * 
     */
    private @Nullable String launchMode;
    /**
     * @return Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptions launchOptions;
    /**
     * @return Custom metadata key/value pairs that you provide, such as the SSH public key required to connect to the instance.
     * 
     */
    private @Nullable Map<String,Object> metadata;
    /**
     * @return The platform configuration requested for the instance.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig platformConfig;
    /**
     * @return Configuration options for preemptible instances.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfig preemptibleInstanceConfig;
    /**
     * @return The preferred maintenance action for an instance. The default is LIVE_MIGRATE, if live migration is supported.
     * 
     */
    private @Nullable String preferredMaintenanceAction;
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    private @Nullable String shape;
    /**
     * @return The shape configuration requested for the instance.
     * 
     */
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig shapeConfig;
    private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetails sourceDetails;

    private InstanceConfigurationInstanceDetailsLaunchDetails() {}
    /**
     * @return Configuration options for the Oracle Cloud Agent software running on the instance.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfig> agentConfig() {
        return Optional.ofNullable(this.agentConfig);
    }
    /**
     * @return Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig> availabilityConfig() {
        return Optional.ofNullable(this.availabilityConfig);
    }
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under.
     * 
     */
    public Optional<String> capacityReservationId() {
        return Optional.ofNullable(this.capacityReservationId);
    }
    /**
     * @return The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetails> createVnicDetails() {
        return Optional.ofNullable(this.createVnicDetails);
    }
    /**
     * @return The OCID of dedicated VM host.
     * 
     */
    public Optional<String> dedicatedVmHostId() {
        return Optional.ofNullable(this.dedicatedVmHostId);
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    public Map<String,Object> extendedMetadata() {
        return this.extendedMetadata == null ? Map.of() : this.extendedMetadata;
    }
    /**
     * @return A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
     * 
     */
    public Optional<String> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return Optional mutable instance options. As a part of Instance Metadata Service Security Header, This allows user to disable the legacy imds endpoints.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptions> instanceOptions() {
        return Optional.ofNullable(this.instanceOptions);
    }
    /**
     * @return This is an advanced option.
     * 
     */
    public Optional<String> ipxeScript() {
        return Optional.ofNullable(this.ipxeScript);
    }
    /**
     * @return Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
     * 
     */
    public Optional<Boolean> isPvEncryptionInTransitEnabled() {
        return Optional.ofNullable(this.isPvEncryptionInTransitEnabled);
    }
    /**
     * @return Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * 
     */
    public Optional<String> launchMode() {
        return Optional.ofNullable(this.launchMode);
    }
    /**
     * @return Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptions> launchOptions() {
        return Optional.ofNullable(this.launchOptions);
    }
    /**
     * @return Custom metadata key/value pairs that you provide, such as the SSH public key required to connect to the instance.
     * 
     */
    public Map<String,Object> metadata() {
        return this.metadata == null ? Map.of() : this.metadata;
    }
    /**
     * @return The platform configuration requested for the instance.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig> platformConfig() {
        return Optional.ofNullable(this.platformConfig);
    }
    /**
     * @return Configuration options for preemptible instances.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfig> preemptibleInstanceConfig() {
        return Optional.ofNullable(this.preemptibleInstanceConfig);
    }
    /**
     * @return The preferred maintenance action for an instance. The default is LIVE_MIGRATE, if live migration is supported.
     * 
     */
    public Optional<String> preferredMaintenanceAction() {
        return Optional.ofNullable(this.preferredMaintenanceAction);
    }
    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    public Optional<String> shape() {
        return Optional.ofNullable(this.shape);
    }
    /**
     * @return The shape configuration requested for the instance.
     * 
     */
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig> shapeConfig() {
        return Optional.ofNullable(this.shapeConfig);
    }
    public Optional<InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetails> sourceDetails() {
        return Optional.ofNullable(this.sourceDetails);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceConfigurationInstanceDetailsLaunchDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfig agentConfig;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig availabilityConfig;
        private @Nullable String availabilityDomain;
        private @Nullable String capacityReservationId;
        private @Nullable String compartmentId;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetails createVnicDetails;
        private @Nullable String dedicatedVmHostId;
        private @Nullable Map<String,Object> definedTags;
        private @Nullable String displayName;
        private @Nullable Map<String,Object> extendedMetadata;
        private @Nullable String faultDomain;
        private @Nullable Map<String,Object> freeformTags;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptions instanceOptions;
        private @Nullable String ipxeScript;
        private @Nullable Boolean isPvEncryptionInTransitEnabled;
        private @Nullable String launchMode;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptions launchOptions;
        private @Nullable Map<String,Object> metadata;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig platformConfig;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfig preemptibleInstanceConfig;
        private @Nullable String preferredMaintenanceAction;
        private @Nullable String shape;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig shapeConfig;
        private @Nullable InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetails sourceDetails;
        public Builder() {}
        public Builder(InstanceConfigurationInstanceDetailsLaunchDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.agentConfig = defaults.agentConfig;
    	      this.availabilityConfig = defaults.availabilityConfig;
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
    	      this.platformConfig = defaults.platformConfig;
    	      this.preemptibleInstanceConfig = defaults.preemptibleInstanceConfig;
    	      this.preferredMaintenanceAction = defaults.preferredMaintenanceAction;
    	      this.shape = defaults.shape;
    	      this.shapeConfig = defaults.shapeConfig;
    	      this.sourceDetails = defaults.sourceDetails;
        }

        @CustomType.Setter
        public Builder agentConfig(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfig agentConfig) {
            this.agentConfig = agentConfig;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityConfig(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfig availabilityConfig) {
            this.availabilityConfig = availabilityConfig;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(@Nullable String capacityReservationId) {
            this.capacityReservationId = capacityReservationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder createVnicDetails(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetails createVnicDetails) {
            this.createVnicDetails = createVnicDetails;
            return this;
        }
        @CustomType.Setter
        public Builder dedicatedVmHostId(@Nullable String dedicatedVmHostId) {
            this.dedicatedVmHostId = dedicatedVmHostId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,Object> definedTags) {
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder extendedMetadata(@Nullable Map<String,Object> extendedMetadata) {
            this.extendedMetadata = extendedMetadata;
            return this;
        }
        @CustomType.Setter
        public Builder faultDomain(@Nullable String faultDomain) {
            this.faultDomain = faultDomain;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,Object> freeformTags) {
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder instanceOptions(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptions instanceOptions) {
            this.instanceOptions = instanceOptions;
            return this;
        }
        @CustomType.Setter
        public Builder ipxeScript(@Nullable String ipxeScript) {
            this.ipxeScript = ipxeScript;
            return this;
        }
        @CustomType.Setter
        public Builder isPvEncryptionInTransitEnabled(@Nullable Boolean isPvEncryptionInTransitEnabled) {
            this.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder launchMode(@Nullable String launchMode) {
            this.launchMode = launchMode;
            return this;
        }
        @CustomType.Setter
        public Builder launchOptions(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptions launchOptions) {
            this.launchOptions = launchOptions;
            return this;
        }
        @CustomType.Setter
        public Builder metadata(@Nullable Map<String,Object> metadata) {
            this.metadata = metadata;
            return this;
        }
        @CustomType.Setter
        public Builder platformConfig(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfig platformConfig) {
            this.platformConfig = platformConfig;
            return this;
        }
        @CustomType.Setter
        public Builder preemptibleInstanceConfig(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfig preemptibleInstanceConfig) {
            this.preemptibleInstanceConfig = preemptibleInstanceConfig;
            return this;
        }
        @CustomType.Setter
        public Builder preferredMaintenanceAction(@Nullable String preferredMaintenanceAction) {
            this.preferredMaintenanceAction = preferredMaintenanceAction;
            return this;
        }
        @CustomType.Setter
        public Builder shape(@Nullable String shape) {
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder shapeConfig(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig shapeConfig) {
            this.shapeConfig = shapeConfig;
            return this;
        }
        @CustomType.Setter
        public Builder sourceDetails(@Nullable InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetails sourceDetails) {
            this.sourceDetails = sourceDetails;
            return this;
        }
        public InstanceConfigurationInstanceDetailsLaunchDetails build() {
            final var o = new InstanceConfigurationInstanceDetailsLaunchDetails();
            o.agentConfig = agentConfig;
            o.availabilityConfig = availabilityConfig;
            o.availabilityDomain = availabilityDomain;
            o.capacityReservationId = capacityReservationId;
            o.compartmentId = compartmentId;
            o.createVnicDetails = createVnicDetails;
            o.dedicatedVmHostId = dedicatedVmHostId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.extendedMetadata = extendedMetadata;
            o.faultDomain = faultDomain;
            o.freeformTags = freeformTags;
            o.instanceOptions = instanceOptions;
            o.ipxeScript = ipxeScript;
            o.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            o.launchMode = launchMode;
            o.launchOptions = launchOptions;
            o.metadata = metadata;
            o.platformConfig = platformConfig;
            o.preemptibleInstanceConfig = preemptibleInstanceConfig;
            o.preferredMaintenanceAction = preferredMaintenanceAction;
            o.shape = shape;
            o.shapeConfig = shapeConfig;
            o.sourceDetails = sourceDetails;
            return o;
        }
    }
}