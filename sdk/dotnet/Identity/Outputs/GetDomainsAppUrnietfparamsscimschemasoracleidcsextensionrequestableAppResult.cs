// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppResult
    {
        /// <summary>
        /// Flag controlling whether resource can be request by user through self service console.
        /// </summary>
        public readonly bool Requestable;

        [OutputConstructor]
        private GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppResult(bool requestable)
        {
            Requestable = requestable;
        }
    }
}
