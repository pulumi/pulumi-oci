// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentAssociatedComponentResult
    {
        /// <summary>
        /// The association type.
        /// </summary>
        public readonly string AssociationType;
        /// <summary>
        /// The identifier of the discovered DB system component.
        /// </summary>
        public readonly string ComponentId;
        /// <summary>
        /// The component type.
        /// </summary>
        public readonly string ComponentType;

        [OutputConstructor]
        private GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemDiscoveredComponentAssociatedComponentResult(
            string associationType,

            string componentId,

            string componentType)
        {
            AssociationType = associationType;
            ComponentId = componentId;
            ComponentType = componentType;
        }
    }
}