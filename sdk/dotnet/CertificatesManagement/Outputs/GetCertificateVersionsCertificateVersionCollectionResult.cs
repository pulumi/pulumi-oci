// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CertificatesManagement.Outputs
{

    [OutputType]
    public sealed class GetCertificateVersionsCertificateVersionCollectionResult
    {
        /// <summary>
        /// A list of certificate version summary objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCertificateVersionsCertificateVersionCollectionItemResult> Items;

        [OutputConstructor]
        private GetCertificateVersionsCertificateVersionCollectionResult(ImmutableArray<Outputs.GetCertificateVersionsCertificateVersionCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
