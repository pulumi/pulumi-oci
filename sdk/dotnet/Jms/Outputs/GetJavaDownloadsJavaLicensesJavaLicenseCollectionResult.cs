// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetJavaDownloadsJavaLicensesJavaLicenseCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetJavaDownloadsJavaLicensesJavaLicenseCollectionItemResult> Items;

        [OutputConstructor]
        private GetJavaDownloadsJavaLicensesJavaLicenseCollectionResult(ImmutableArray<Outputs.GetJavaDownloadsJavaLicensesJavaLicenseCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
