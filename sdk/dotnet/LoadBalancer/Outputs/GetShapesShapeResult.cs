// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetShapesShapeResult
    {
        /// <summary>
        /// The name of the shape.  Example: `100Mbps`
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetShapesShapeResult(string name)
        {
            Name = name;
        }
    }
}
