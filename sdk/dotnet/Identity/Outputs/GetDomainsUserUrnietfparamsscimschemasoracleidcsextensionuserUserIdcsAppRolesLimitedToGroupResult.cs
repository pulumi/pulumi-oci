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
    public sealed class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserIdcsAppRolesLimitedToGroupResult
    {
        /// <summary>
        /// A human readable name, primarily used for display purposes.
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// The id of the Oracle Identity Cloud Service AppRole grant limited to one or more Groups.
        /// </summary>
        public readonly string IdcsAppRoleId;
        /// <summary>
        /// The OCID of the user's support account.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// User Token URI
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// The value of a X509 certificate.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserIdcsAppRolesLimitedToGroupResult(
            string display,

            string idcsAppRoleId,

            string ocid,

            string @ref,

            string value)
        {
            Display = display;
            IdcsAppRoleId = idcsAppRoleId;
            Ocid = ocid;
            Ref = @ref;
            Value = value;
        }
    }
}
