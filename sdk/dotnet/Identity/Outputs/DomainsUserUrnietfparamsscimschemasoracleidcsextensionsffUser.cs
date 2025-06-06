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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUser
    {
        /// <summary>
        /// (Updatable) SFF auth keys clob
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? SffAuthKeys;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionsffUser(string? sffAuthKeys)
        {
            SffAuthKeys = sffAuthKeys;
        }
    }
}
