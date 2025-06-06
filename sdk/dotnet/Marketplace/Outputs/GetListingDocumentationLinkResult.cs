// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace.Outputs
{

    [OutputType]
    public sealed class GetListingDocumentationLinkResult
    {
        /// <summary>
        /// The category that the document belongs to.
        /// </summary>
        public readonly string DocumentCategory;
        /// <summary>
        /// Text that describes the resource.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The URL of the resource.
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private GetListingDocumentationLinkResult(
            string documentCategory,

            string name,

            string url)
        {
            DocumentCategory = documentCategory;
            Name = name;
            Url = url;
        }
    }
}
