// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class DeployStageContainerConfig
    {
        /// <summary>
        /// (Updatable) Availability domain where the ContainerInstance will be created.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// (Updatable) The OCID of the compartment where the ContainerInstance will be created.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// (Updatable) Container configuration type.
        /// </summary>
        public readonly string ContainerConfigType;
        /// <summary>
        /// (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
        /// </summary>
        public readonly Outputs.DeployStageContainerConfigNetworkChannel NetworkChannel;
        /// <summary>
        /// (Updatable) Determines the size and amount of resources available to the instance.
        /// </summary>
        public readonly Outputs.DeployStageContainerConfigShapeConfig ShapeConfig;
        /// <summary>
        /// (Updatable) The shape of the ContainerInstance. The shape determines the resources available to the ContainerInstance.
        /// </summary>
        public readonly string ShapeName;

        [OutputConstructor]
        private DeployStageContainerConfig(
            string? availabilityDomain,

            string? compartmentId,

            string containerConfigType,

            Outputs.DeployStageContainerConfigNetworkChannel networkChannel,

            Outputs.DeployStageContainerConfigShapeConfig shapeConfig,

            string shapeName)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            ContainerConfigType = containerConfigType;
            NetworkChannel = networkChannel;
            ShapeConfig = shapeConfig;
            ShapeName = shapeName;
        }
    }
}