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
    public sealed class GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionradiusAppAppResult
    {
        /// <summary>
        /// If true, capture the client IP address from the RADIUS request packet. IP Address is used for auditing, policy-evaluation and country-code calculation.
        /// </summary>
        public readonly bool CaptureClientIp;
        /// <summary>
        /// This is the IP address of the RADIUS Client like Oracle Database server. It can be only IP address and not hostname.
        /// </summary>
        public readonly string ClientIp;
        /// <summary>
        /// Vendor-specific identifier of the attribute in the RADIUS response that will contain the end-user's country code. This is an integer-value in the range 1 to 255
        /// </summary>
        public readonly string CountryCodeResponseAttributeId;
        /// <summary>
        /// The name of the attribute that contains the Internet Protocol address of the end-user.
        /// </summary>
        public readonly string EndUserIpAttribute;
        /// <summary>
        /// RADIUS attribute that RADIUS-enabled system uses to pass the group membership
        /// </summary>
        public readonly string GroupMembershipRadiusAttribute;
        /// <summary>
        /// In a successful authentication response, Oracle Identity Cloud Service will pass user's group information restricted to groups persisted in this attribute, in the specified RADIUS attribute.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionradiusAppAppGroupMembershipToReturnResult> GroupMembershipToReturns;
        /// <summary>
        /// Configure the groupNameFormat based on vendor in order to pass it to RADIUS infra
        /// </summary>
        public readonly string GroupNameFormat;
        /// <summary>
        /// Indicates to include groups in RADIUS response
        /// </summary>
        public readonly bool IncludeGroupInResponse;
        /// <summary>
        /// Indicates if password and OTP are passed in the same sign-in request or not.
        /// </summary>
        public readonly bool PasswordAndOtpTogether;
        /// <summary>
        /// This is the port of RADIUS Proxy which RADIUS client will connect to.
        /// </summary>
        public readonly string Port;
        /// <summary>
        /// ID used to identify a particular vendor.
        /// </summary>
        public readonly string RadiusVendorSpecificId;
        /// <summary>
        /// Configure the responseFormat based on vendor in order to pass it to RADIUS infra
        /// </summary>
        public readonly string ResponseFormat;
        /// <summary>
        /// The delimiter used if group membership responseFormat is a delimited list instead of repeating attributes
        /// </summary>
        public readonly string ResponseFormatDelimiter;
        /// <summary>
        /// Secret key used to secure communication between RADIUS Proxy and RADIUS client
        /// </summary>
        public readonly string SecretKey;
        /// <summary>
        /// Value consists of type of RADIUS App. Type can be Oracle Database, VPN etc
        /// </summary>
        public readonly string TypeOfRadiusApp;

        [OutputConstructor]
        private GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionradiusAppAppResult(
            bool captureClientIp,

            string clientIp,

            string countryCodeResponseAttributeId,

            string endUserIpAttribute,

            string groupMembershipRadiusAttribute,

            ImmutableArray<Outputs.GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionradiusAppAppGroupMembershipToReturnResult> groupMembershipToReturns,

            string groupNameFormat,

            bool includeGroupInResponse,

            bool passwordAndOtpTogether,

            string port,

            string radiusVendorSpecificId,

            string responseFormat,

            string responseFormatDelimiter,

            string secretKey,

            string typeOfRadiusApp)
        {
            CaptureClientIp = captureClientIp;
            ClientIp = clientIp;
            CountryCodeResponseAttributeId = countryCodeResponseAttributeId;
            EndUserIpAttribute = endUserIpAttribute;
            GroupMembershipRadiusAttribute = groupMembershipRadiusAttribute;
            GroupMembershipToReturns = groupMembershipToReturns;
            GroupNameFormat = groupNameFormat;
            IncludeGroupInResponse = includeGroupInResponse;
            PasswordAndOtpTogether = passwordAndOtpTogether;
            Port = port;
            RadiusVendorSpecificId = radiusVendorSpecificId;
            ResponseFormat = responseFormat;
            ResponseFormatDelimiter = responseFormatDelimiter;
            SecretKey = secretKey;
            TypeOfRadiusApp = typeOfRadiusApp;
        }
    }
}