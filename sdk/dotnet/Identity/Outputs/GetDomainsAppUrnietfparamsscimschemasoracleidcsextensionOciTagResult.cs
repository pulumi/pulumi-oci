// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagResult
    {
        /// <summary>
        /// Oracle Cloud Infrastructure Defined Tags
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTagResult> DefinedTags;
        /// <summary>
        /// Oracle Cloud Infrastructure Freeform Tags
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagFreeformTagResult> FreeformTags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tag slug
        /// </summary>
        public readonly string TagSlug;

        [OutputConstructor]
        private GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagResult(
            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTagResult> definedTags,

            ImmutableArray<Outputs.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagFreeformTagResult> freeformTags,

            string tagSlug)
        {
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            TagSlug = tagSlug;
        }
    }
}