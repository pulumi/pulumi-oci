// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAuthenticationFactorSettingThirdPartyFactorGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) To enable Duo Security factor
        /// </summary>
        [Input("duoSecurity", required: true)]
        public Input<bool> DuoSecurity { get; set; } = null!;

        public DomainsAuthenticationFactorSettingThirdPartyFactorGetArgs()
        {
        }
        public static new DomainsAuthenticationFactorSettingThirdPartyFactorGetArgs Empty => new DomainsAuthenticationFactorSettingThirdPartyFactorGetArgs();
    }
}