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
    public sealed class GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserResult
    {
        /// <summary>
        /// If true, allows requesting user to update themselves. If false, requesting user can't update themself (default).
        /// </summary>
        public readonly bool AllowSelfChange;

        [OutputConstructor]
        private GetDomainsApiKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserResult(bool allowSelfChange)
        {
            AllowSelfChange = allowSelfChange;
        }
    }
}