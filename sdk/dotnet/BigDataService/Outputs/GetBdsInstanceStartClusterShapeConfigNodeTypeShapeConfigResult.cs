// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfigResult
    {
        /// <summary>
        /// Cluster node type.
        /// </summary>
        public readonly string NodeType;
        /// <summary>
        /// Shape of the node.
        /// </summary>
        public readonly string Shape;

        [OutputConstructor]
        private GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfigResult(
            string nodeType,

            string shape)
        {
            NodeType = nodeType;
            Shape = shape;
        }
    }
}
