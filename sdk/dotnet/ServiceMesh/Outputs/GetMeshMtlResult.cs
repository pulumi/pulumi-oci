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
    public sealed class GetMeshMtlResult
    {
        /// <summary>
        /// DISABLED: No minimum virtual services within this mesh can use any mTLS authentication mode. PERMISSIVE: Virtual services within this mesh can use either PERMISSIVE or STRICT modes. STRICT: All virtual services within this mesh must use STRICT mode.
        /// </summary>
        public readonly string Minimum;

        [OutputConstructor]
        private GetMeshMtlResult(string minimum)
        {
            Minimum = minimum;
        }
    }
}