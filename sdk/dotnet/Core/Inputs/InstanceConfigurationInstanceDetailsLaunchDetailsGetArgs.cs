// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsLaunchDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Configuration options for the Oracle Cloud Agent software running on the instance.
        /// </summary>
        [Input("agentConfig")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigGetArgs>? AgentConfig { get; set; }

        /// <summary>
        /// Options for defining the availabiity of a VM instance after a maintenance event that impacts the underlying hardware.
        /// </summary>
        [Input("availabilityConfig")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfigGetArgs>? AvailabilityConfig { get; set; }

        /// <summary>
        /// The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The OCID of the compute capacity reservation this instance is launched under.
        /// </summary>
        [Input("capacityReservationId")]
        public Input<string>? CapacityReservationId { get; set; }

        /// <summary>
        /// The OCID of the compartment containing the instance. Instances created from instance configurations are placed in the same compartment as the instance that was used to create the instance configuration.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Contains the properties of the VNIC for an instance configuration. See [CreateVnicDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/CreateVnicDetails/) and [Instance Configurations](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm#config) for more information.
        /// </summary>
        [Input("createVnicDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetailsGetArgs>? CreateVnicDetails { get; set; }

        /// <summary>
        /// The OCID of dedicated VM host.
        /// </summary>
        [Input("dedicatedVmHostId")]
        public Input<string>? DedicatedVmHostId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("extendedMetadata")]
        private InputMap<object>? _extendedMetadata;

        /// <summary>
        /// Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
        /// </summary>
        public InputMap<object> ExtendedMetadata
        {
            get => _extendedMetadata ?? (_extendedMetadata = new InputMap<object>());
            set => _extendedMetadata = value;
        }

        /// <summary>
        /// A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Optional mutable instance options. As a part of Instance Metadata Service Security Header, This allows user to disable the legacy imds endpoints.
        /// </summary>
        [Input("instanceOptions")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptionsGetArgs>? InstanceOptions { get; set; }

        /// <summary>
        /// This is an advanced option.
        /// </summary>
        [Input("ipxeScript")]
        public Input<string>? IpxeScript { get; set; }

        /// <summary>
        /// Deprecated. Instead use `isPvEncryptionInTransitEnabled` in [InstanceConfigurationLaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/datatypes/InstanceConfigurationLaunchInstanceDetails).
        /// </summary>
        [Input("isPvEncryptionInTransitEnabled")]
        public Input<bool>? IsPvEncryptionInTransitEnabled { get; set; }

        /// <summary>
        /// Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
        /// </summary>
        [Input("launchMode")]
        public Input<string>? LaunchMode { get; set; }

        /// <summary>
        /// Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
        /// </summary>
        [Input("launchOptions")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptionsGetArgs>? LaunchOptions { get; set; }

        [Input("metadata")]
        private InputMap<object>? _metadata;

        /// <summary>
        /// Custom metadata key/value pairs that you provide, such as the SSH public key required to connect to the instance.
        /// </summary>
        public InputMap<object> Metadata
        {
            get => _metadata ?? (_metadata = new InputMap<object>());
            set => _metadata = value;
        }

        /// <summary>
        /// The platform configuration requested for the instance.
        /// </summary>
        [Input("platformConfig")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfigGetArgs>? PlatformConfig { get; set; }

        /// <summary>
        /// Configuration options for preemptible instances.
        /// </summary>
        [Input("preemptibleInstanceConfig")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigGetArgs>? PreemptibleInstanceConfig { get; set; }

        /// <summary>
        /// The preferred maintenance action for an instance. The default is LIVE_MIGRATE, if live migration is supported.
        /// </summary>
        [Input("preferredMaintenanceAction")]
        public Input<string>? PreferredMaintenanceAction { get; set; }

        /// <summary>
        /// The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
        /// </summary>
        [Input("shape")]
        public Input<string>? Shape { get; set; }

        /// <summary>
        /// The shape configuration requested for the instance.
        /// </summary>
        [Input("shapeConfig")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfigGetArgs>? ShapeConfig { get; set; }

        [Input("sourceDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetailsGetArgs>? SourceDetails { get; set; }

        public InstanceConfigurationInstanceDetailsLaunchDetailsGetArgs()
        {
        }
        public static new InstanceConfigurationInstanceDetailsLaunchDetailsGetArgs Empty => new InstanceConfigurationInstanceDetailsLaunchDetailsGetArgs();
    }
}