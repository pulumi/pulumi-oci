// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class PolicyWafConfigCachingRuleCriteriaArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The condition of the caching rule criteria.
        /// * **URL_IS:** Matches if the concatenation of request URL path and query is identical to the contents of the `value` field.
        /// * **URL_STARTS_WITH:** Matches if the concatenation of request URL path and query starts with the contents of the `value` field.
        /// * **URL_PART_ENDS_WITH:** Matches if the concatenation of request URL path and query ends with the contents of the `value` field.
        /// * **URL_PART_CONTAINS:** Matches if the concatenation of request URL path and query contains the contents of the `value` field.
        /// 
        /// URLs must start with a `/`. URLs can't contain restricted double slashes `//`. URLs can't contain the restricted `'` `&amp;` `?` symbols. Resources to cache can only be specified by a URL, any query parameters are ignored.
        /// </summary>
        [Input("condition", required: true)]
        public Input<string> Condition { get; set; } = null!;

        /// <summary>
        /// (Updatable) The value of the caching rule criteria.
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public PolicyWafConfigCachingRuleCriteriaArgs()
        {
        }
        public static new PolicyWafConfigCachingRuleCriteriaArgs Empty => new PolicyWafConfigCachingRuleCriteriaArgs();
    }
}
