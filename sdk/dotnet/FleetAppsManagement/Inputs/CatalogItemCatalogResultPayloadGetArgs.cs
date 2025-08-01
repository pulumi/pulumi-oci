// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class CatalogItemCatalogResultPayloadGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// branch Name
        /// </summary>
        [Input("branchName")]
        public Input<string>? BranchName { get; set; }

        /// <summary>
        /// config result type.
        /// </summary>
        [Input("configResultType")]
        public Input<string>? ConfigResultType { get; set; }

        /// <summary>
        /// configuration Source Provider [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("configurationSourceProviderId")]
        public Input<string>? ConfigurationSourceProviderId { get; set; }

        /// <summary>
        /// package url
        /// </summary>
        [Input("packageUrl")]
        public Input<string>? PackageUrl { get; set; }

        /// <summary>
        /// repository Url
        /// </summary>
        [Input("repositoryUrl")]
        public Input<string>? RepositoryUrl { get; set; }

        /// <summary>
        /// template id
        /// </summary>
        [Input("templateId")]
        public Input<string>? TemplateId { get; set; }

        /// <summary>
        /// The date and time expires, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeExpires")]
        public Input<string>? TimeExpires { get; set; }

        [Input("workingDirectory")]
        public Input<string>? WorkingDirectory { get; set; }

        public CatalogItemCatalogResultPayloadGetArgs()
        {
        }
        public static new CatalogItemCatalogResultPayloadGetArgs Empty => new CatalogItemCatalogResultPayloadGetArgs();
    }
}
