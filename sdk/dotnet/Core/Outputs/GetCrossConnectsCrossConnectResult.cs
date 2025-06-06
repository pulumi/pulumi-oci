// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetCrossConnectsCrossConnectResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cross-connect group.
        /// </summary>
        public readonly string CrossConnectGroupId;
        /// <summary>
        /// A reference name or identifier for the physical fiber connection that this cross-connect uses.
        /// </summary>
        public readonly string CustomerReferenceName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        public readonly string FarCrossConnectOrCrossConnectGroupId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The cross-connect's Oracle ID (OCID).
        /// </summary>
        public readonly string Id;
        public readonly bool IsActive;
        /// <summary>
        /// The name of the FastConnect location where this cross-connect is installed.
        /// </summary>
        public readonly string LocationName;
        /// <summary>
        /// Properties used for MACsec (if capable).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCrossConnectsCrossConnectMacsecPropertyResult> MacsecProperties;
        public readonly string NearCrossConnectOrCrossConnectGroupId;
        /// <summary>
        /// The FastConnect device that terminates the logical connection. This device might be different than the device that terminates the physical connection.
        /// </summary>
        public readonly string OciLogicalDeviceName;
        /// <summary>
        /// The FastConnect device that terminates the physical connection.
        /// </summary>
        public readonly string OciPhysicalDeviceName;
        /// <summary>
        /// A string identifying the meet-me room port for this cross-connect.
        /// </summary>
        public readonly string PortName;
        /// <summary>
        /// The port speed for this cross-connect.  Example: `10 Gbps`
        /// </summary>
        public readonly string PortSpeedShapeName;
        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the cross-connect was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetCrossConnectsCrossConnectResult(
            string compartmentId,

            string crossConnectGroupId,

            string customerReferenceName,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string farCrossConnectOrCrossConnectGroupId,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isActive,

            string locationName,

            ImmutableArray<Outputs.GetCrossConnectsCrossConnectMacsecPropertyResult> macsecProperties,

            string nearCrossConnectOrCrossConnectGroupId,

            string ociLogicalDeviceName,

            string ociPhysicalDeviceName,

            string portName,

            string portSpeedShapeName,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            CrossConnectGroupId = crossConnectGroupId;
            CustomerReferenceName = customerReferenceName;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FarCrossConnectOrCrossConnectGroupId = farCrossConnectOrCrossConnectGroupId;
            FreeformTags = freeformTags;
            Id = id;
            IsActive = isActive;
            LocationName = locationName;
            MacsecProperties = macsecProperties;
            NearCrossConnectOrCrossConnectGroupId = nearCrossConnectOrCrossConnectGroupId;
            OciLogicalDeviceName = ociLogicalDeviceName;
            OciPhysicalDeviceName = ociPhysicalDeviceName;
            PortName = portName;
            PortSpeedShapeName = portSpeedShapeName;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
