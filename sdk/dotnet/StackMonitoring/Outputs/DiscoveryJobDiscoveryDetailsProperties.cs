// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class DiscoveryJobDiscoveryDetailsProperties
    {
        /// <summary>
        /// Key/Value pair of Property
        /// </summary>
        public readonly ImmutableDictionary<string, object>? PropertiesMap;

        [OutputConstructor]
        private DiscoveryJobDiscoveryDetailsProperties(ImmutableDictionary<string, object>? propertiesMap)
        {
            PropertiesMap = propertiesMap;
        }
    }
}