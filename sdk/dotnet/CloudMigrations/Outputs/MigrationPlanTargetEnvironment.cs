// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Outputs
{

    [OutputType]
    public sealed class MigrationPlanTargetEnvironment
    {
        /// <summary>
        /// (Updatable) Availability Domain of the VM configuration.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// (Updatable) OCID of the dedicated VM configuration host.
        /// </summary>
        public readonly string? DedicatedVmHost;
        /// <summary>
        /// (Updatable) Fault domain of the VM configuration.
        /// </summary>
        public readonly string? FaultDomain;
        /// <summary>
        /// (Updatable) Microsoft license for the VM configuration.
        /// </summary>
        public readonly string? MsLicense;
        /// <summary>
        /// (Updatable) Preferred VM shape type provided by the customer.
        /// </summary>
        public readonly string? PreferredShapeType;
        /// <summary>
        /// (Updatable) OCID of the VM configuration subnet.
        /// </summary>
        public readonly string Subnet;
        /// <summary>
        /// (Updatable) Target compartment identifier
        /// </summary>
        public readonly string? TargetCompartmentId;
        /// <summary>
        /// (Updatable) The type of target environment.
        /// </summary>
        public readonly string TargetEnvironmentType;
        /// <summary>
        /// (Updatable) OCID of the VM configuration VCN.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string Vcn;

        [OutputConstructor]
        private MigrationPlanTargetEnvironment(
            string? availabilityDomain,

            string? dedicatedVmHost,

            string? faultDomain,

            string? msLicense,

            string? preferredShapeType,

            string subnet,

            string? targetCompartmentId,

            string targetEnvironmentType,

            string vcn)
        {
            AvailabilityDomain = availabilityDomain;
            DedicatedVmHost = dedicatedVmHost;
            FaultDomain = faultDomain;
            MsLicense = msLicense;
            PreferredShapeType = preferredShapeType;
            Subnet = subnet;
            TargetCompartmentId = targetCompartmentId;
            TargetEnvironmentType = targetEnvironmentType;
            Vcn = vcn;
        }
    }
}
