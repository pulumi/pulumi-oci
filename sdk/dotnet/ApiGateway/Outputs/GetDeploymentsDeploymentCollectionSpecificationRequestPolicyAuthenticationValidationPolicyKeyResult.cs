// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationPolicyKeyResult
    {
        /// <summary>
        /// The algorithm intended for use with this key.
        /// </summary>
        public readonly string Alg;
        /// <summary>
        /// The base64 url encoded exponent of the RSA public key represented by this key.
        /// </summary>
        public readonly string E;
        /// <summary>
        /// The format of the public key.
        /// </summary>
        public readonly string Format;
        /// <summary>
        /// Information around the values for selector of an authentication/ routing branch.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The operations for which this key is to be used.
        /// </summary>
        public readonly ImmutableArray<string> KeyOps;
        /// <summary>
        /// A unique key ID. This key will be used to verify the signature of a JWT with matching "kid".
        /// </summary>
        public readonly string Kid;
        /// <summary>
        /// The key type.
        /// </summary>
        public readonly string Kty;
        /// <summary>
        /// The base64 url encoded modulus of the RSA public key represented by this key.
        /// </summary>
        public readonly string N;
        /// <summary>
        /// The intended use of the public key.
        /// </summary>
        public readonly string Use;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationPolicyKeyResult(
            string alg,

            string e,

            string format,

            string key,

            ImmutableArray<string> keyOps,

            string kid,

            string kty,

            string n,

            string use)
        {
            Alg = alg;
            E = e;
            Format = format;
            Key = key;
            KeyOps = keyOps;
            Kid = kid;
            Kty = kty;
            N = n;
            Use = use;
        }
    }
}