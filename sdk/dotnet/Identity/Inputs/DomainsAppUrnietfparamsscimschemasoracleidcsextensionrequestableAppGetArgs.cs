// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Flag controlling whether resource can be request by user through self service console.
        /// 
        /// **Added In:** 17.3.4
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("requestable")]
        public Input<bool>? Requestable { get; set; }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppGetArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppGetArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppGetArgs();
    }
}
