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
    public sealed class GetVirtualServiceDefaultRoutingPolicyResult
    {
        /// <summary>
        /// Type of the virtual service routing policy.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetVirtualServiceDefaultRoutingPolicyResult(string type)
        {
            Type = type;
        }
    }
}