// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waa.Inputs
{

    public sealed class AppAccelerationPolicyResponseCachingPolicyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) When false, responses will not be cached by the backend based on response headers.
        /// 
        /// When true, responses that contain one of the supported cache control headers will be cached according to the values specified in the cache control headers.
        /// 
        /// The "X-Accel-Expires" header field sets caching time of a response in seconds. The zero value disables caching for a response. If the value starts with the @ prefix, it sets an absolute time in seconds since Epoch, up to which the response may be cached.
        /// 
        /// If the header does not include the "X-Accel-Expires" field, parameters of caching may be set in the header fields "Expires" or "Cache-Control".
        /// 
        /// If the header includes the "Set-Cookie" field, such a response will not be cached.
        /// 
        /// If the header includes the "Vary" field with the special value "*", such a response will not be cached. If the header includes the "Vary" field with another value, such a response will be cached taking into account the corresponding request header fields.
        /// </summary>
        [Input("isResponseHeaderBasedCachingEnabled")]
        public Input<bool>? IsResponseHeaderBasedCachingEnabled { get; set; }

        public AppAccelerationPolicyResponseCachingPolicyGetArgs()
        {
        }
        public static new AppAccelerationPolicyResponseCachingPolicyGetArgs Empty => new AppAccelerationPolicyResponseCachingPolicyGetArgs();
    }
}
