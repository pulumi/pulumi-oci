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
    public sealed class GetMeshesMeshCollectionItemCertificateAuthorityResult
    {
        /// <summary>
        /// Unique Mesh identifier.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetMeshesMeshCollectionItemCertificateAuthorityResult(string id)
        {
            Id = id;
        }
    }
}
