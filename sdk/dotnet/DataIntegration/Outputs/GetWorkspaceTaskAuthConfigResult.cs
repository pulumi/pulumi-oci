// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Outputs
{

    [OutputType]
    public sealed class GetWorkspaceTaskAuthConfigResult
    {
        /// <summary>
        /// The key of the object.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The type of the types object.
        /// </summary>
        public readonly string ModelType;
        /// <summary>
        /// The model version of an object.
        /// </summary>
        public readonly string ModelVersion;
        /// <summary>
        /// A reference to the object's parent.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkspaceTaskAuthConfigParentRefResult> ParentReves;
        /// <summary>
        /// The Oracle Cloud Infrastructure resource type that will supply the authentication token
        /// </summary>
        public readonly string ResourcePrincipalSource;

        [OutputConstructor]
        private GetWorkspaceTaskAuthConfigResult(
            string key,

            string modelType,

            string modelVersion,

            ImmutableArray<Outputs.GetWorkspaceTaskAuthConfigParentRefResult> parentReves,

            string resourcePrincipalSource)
        {
            Key = key;
            ModelType = modelType;
            ModelVersion = modelVersion;
            ParentReves = parentReves;
            ResourcePrincipalSource = resourcePrincipalSource;
        }
    }
}
