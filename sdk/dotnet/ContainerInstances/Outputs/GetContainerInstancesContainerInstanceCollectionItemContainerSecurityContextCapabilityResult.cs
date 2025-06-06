// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerInstances.Outputs
{

    [OutputType]
    public sealed class GetContainerInstancesContainerInstanceCollectionItemContainerSecurityContextCapabilityResult
    {
        public readonly ImmutableArray<string> AddCapabilities;
        public readonly ImmutableArray<string> DropCapabilities;

        [OutputConstructor]
        private GetContainerInstancesContainerInstanceCollectionItemContainerSecurityContextCapabilityResult(
            ImmutableArray<string> addCapabilities,

            ImmutableArray<string> dropCapabilities)
        {
            AddCapabilities = addCapabilities;
            DropCapabilities = dropCapabilities;
        }
    }
}
