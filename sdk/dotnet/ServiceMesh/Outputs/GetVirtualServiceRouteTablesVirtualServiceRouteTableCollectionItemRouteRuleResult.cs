// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Outputs
{

    [OutputType]
    public sealed class GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleResult
    {
        /// <summary>
        /// The destination of the request.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestinationResult> Destinations;
        /// <summary>
        /// If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
        /// </summary>
        public readonly bool IsGrpc;
        /// <summary>
        /// Route to match
        /// </summary>
        public readonly string Path;
        /// <summary>
        /// Match type for the route
        /// </summary>
        public readonly string PathType;
        /// <summary>
        /// Type of protocol.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleResult(
            ImmutableArray<Outputs.GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestinationResult> destinations,

            bool isGrpc,

            string path,

            string pathType,

            string type)
        {
            Destinations = destinations;
            IsGrpc = isGrpc;
            Path = path;
            PathType = pathType;
            Type = type;
        }
    }
}