// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Password Policy resource in Oracle Cloud Infrastructure Identity Domains service.
//
// # Get a Password Policy
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Identity.GetDomainsPasswordPolicy(ctx, &identity.GetDomainsPasswordPolicyArgs{
//				IdcsEndpoint:              data.Oci_identity_domain.Test_domain.Url,
//				PasswordPolicyId:          oci_identity_policy.Test_policy.Id,
//				AttributeSets:             []interface{}{},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(_var.Password_policy_authorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(_var.Password_policy_resource_type_schema_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsPasswordPolicy(ctx *pulumi.Context, args *LookupDomainsPasswordPolicyArgs, opts ...pulumi.InvokeOption) (*LookupDomainsPasswordPolicyResult, error) {
	var rv LookupDomainsPasswordPolicyResult
	err := ctx.Invoke("oci:Identity/getDomainsPasswordPolicy:getDomainsPasswordPolicy", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsPasswordPolicy.
type LookupDomainsPasswordPolicyArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets []string `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes *string `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// ID of the resource
	PasswordPolicyId string `pulumi:"passwordPolicyId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsPasswordPolicy.
type LookupDomainsPasswordPolicyResult struct {
	// A String value whose contents indicate a set of characters that can appear, in any sequence, in a password value
	AllowedChars  string   `pulumi:"allowedChars"`
	AttributeSets []string `pulumi:"attributeSets"`
	Attributes    *string  `pulumi:"attributes"`
	Authorization *string  `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// List of password policy rules that have values set. This map of stringKey:stringValue pairs can be used to aid users while setting/resetting password
	ConfiguredPasswordPolicyRules []GetDomainsPasswordPolicyConfiguredPasswordPolicyRule `pulumi:"configuredPasswordPolicyRules"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// A String that describes the password policy
	Description string `pulumi:"description"`
	// A delimiter used to separate characters in the dictionary file
	DictionaryDelimiter string `pulumi:"dictionaryDelimiter"`
	// A Reference value that contains the URI of a dictionary of words not allowed to appear within a password value
	DictionaryLocation string `pulumi:"dictionaryLocation"`
	// Indicates whether the password can match a dictionary word
	DictionaryWordDisallowed bool `pulumi:"dictionaryWordDisallowed"`
	// A String value whose contents indicate a set of characters that cannot appear, in any sequence, in a password value
	DisallowedChars string `pulumi:"disallowedChars"`
	// A String value whose contents indicate a set of substrings that cannot appear, in any sequence, in a password value
	DisallowedSubstrings []string `pulumi:"disallowedSubstrings"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
	ExternalId string `pulumi:"externalId"`
	// Indicates a sequence of characters that match the user's first name of given name cannot be the password. Password validation against policy will be ignored if length of first name is less than or equal to 3 characters.
	FirstNameDisallowed bool `pulumi:"firstNameDisallowed"`
	// Indicates whether all of the users should be forced to reset their password on the next login (to comply with new password policy changes)
	ForcePasswordReset bool `pulumi:"forcePasswordReset"`
	// A list of groups that the password policy belongs to.
	Groups []GetDomainsPasswordPolicyGroup `pulumi:"groups"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsPasswordPolicyIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                  `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsPasswordPolicyIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// Indicates a sequence of characters that match the user's last name of given name cannot be the password. Password validation against policy will be ignored if length of last name is less than or equal to 3 characters.
	LastNameDisallowed bool `pulumi:"lastNameDisallowed"`
	// The time period in minutes to lock out a user account when the threshold of invalid login attempts is reached. The available range is from 5 through 1440 minutes (24 hours).
	LockoutDuration int `pulumi:"lockoutDuration"`
	// An integer that represents the maximum number of failed logins before an account is locked
	MaxIncorrectAttempts int `pulumi:"maxIncorrectAttempts"`
	// The maximum password length (in characters). A value of 0 or no value indicates no maximum length restriction.
	MaxLength int `pulumi:"maxLength"`
	// The maximum number of repeated characters allowed in a password.  A value of 0 or no value indicates no such restriction.
	MaxRepeatedChars int `pulumi:"maxRepeatedChars"`
	// The maximum number of special characters in a password.  A value of 0 or no value indicates no maximum special characters restriction.
	MaxSpecialChars int `pulumi:"maxSpecialChars"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []GetDomainsPasswordPolicyMeta `pulumi:"metas"`
	// The minimum number of a combination of alphabetic and numeric characters in a password.  A value of 0 or no value indicates no minimum alphanumeric character restriction.
	MinAlphaNumerals int `pulumi:"minAlphaNumerals"`
	// The minimum number of alphabetic characters in a password.  A value of 0 or no value indicates no minimum alphas restriction.
	MinAlphas int `pulumi:"minAlphas"`
	// The minimum password length (in characters). A value of 0 or no value indicates no minimum length restriction.
	MinLength int `pulumi:"minLength"`
	// The minimum number of lowercase alphabetic characters in a password.  A value of 0 or no value indicates no minimum lowercase restriction.
	MinLowerCase int `pulumi:"minLowerCase"`
	// The minimum number of numeric characters in a password.  A value of 0 or no value indicates no minimum numeric character restriction.
	MinNumerals int `pulumi:"minNumerals"`
	// Minimum time after which the user can resubmit the reset password request
	MinPasswordAge int `pulumi:"minPasswordAge"`
	// The minimum number of special characters in a password. A value of 0 or no value indicates no minimum special characters restriction.
	MinSpecialChars int `pulumi:"minSpecialChars"`
	// The minimum number of unique characters in a password.  A value of 0 or no value indicates no minimum unique characters restriction.
	MinUniqueChars int `pulumi:"minUniqueChars"`
	// The minimum number of uppercase alphabetic characters in a password. A value of 0 or no value indicates no minimum uppercase restriction.
	MinUpperCase int `pulumi:"minUpperCase"`
	// A String that is the name of the policy to display to the user. This is the only mandatory attribute for a password policy.
	Name string `pulumi:"name"`
	// The number of passwords that will be kept in history that may not be used as a password
	NumPasswordsInHistory int `pulumi:"numPasswordsInHistory"`
	// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
	Ocid string `pulumi:"ocid"`
	// An integer indicating the number of days before which the user should be warned about password expiry.
	PasswordExpireWarning int `pulumi:"passwordExpireWarning"`
	// The number of days after which the password expires automatically
	PasswordExpiresAfter int    `pulumi:"passwordExpiresAfter"`
	PasswordPolicyId     string `pulumi:"passwordPolicyId"`
	// Indicates whether the password policy is configured as Simple, Standard, or Custom.
	PasswordStrength string `pulumi:"passwordStrength"`
	// Password policy priority
	Priority int `pulumi:"priority"`
	// A String value whose contents indicate a set of characters that must appear, in any sequence, in a password value
	RequiredChars             string  `pulumi:"requiredChars"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// Indicates that the password must begin with an alphabetic character
	StartsWithAlphabet bool `pulumi:"startsWithAlphabet"`
	// A list of tags on this resource.
	Tags []GetDomainsPasswordPolicyTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// Indicates a sequence of characters that match the username cannot be the password. Password validation against policy will be ignored if length of user name is less than or equal to 3 characters.
	UserNameDisallowed bool `pulumi:"userNameDisallowed"`
}

func LookupDomainsPasswordPolicyOutput(ctx *pulumi.Context, args LookupDomainsPasswordPolicyOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsPasswordPolicyResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDomainsPasswordPolicyResult, error) {
			args := v.(LookupDomainsPasswordPolicyArgs)
			r, err := LookupDomainsPasswordPolicy(ctx, &args, opts...)
			var s LookupDomainsPasswordPolicyResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDomainsPasswordPolicyResultOutput)
}

// A collection of arguments for invoking getDomainsPasswordPolicy.
type LookupDomainsPasswordPolicyOutputArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets pulumi.StringArrayInput `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes pulumi.StringPtrInput `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// ID of the resource
	PasswordPolicyId pulumi.StringInput `pulumi:"passwordPolicyId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsPasswordPolicyOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsPasswordPolicyArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsPasswordPolicy.
type LookupDomainsPasswordPolicyResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsPasswordPolicyResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsPasswordPolicyResult)(nil)).Elem()
}

func (o LookupDomainsPasswordPolicyResultOutput) ToLookupDomainsPasswordPolicyResultOutput() LookupDomainsPasswordPolicyResultOutput {
	return o
}

func (o LookupDomainsPasswordPolicyResultOutput) ToLookupDomainsPasswordPolicyResultOutputWithContext(ctx context.Context) LookupDomainsPasswordPolicyResultOutput {
	return o
}

// A String value whose contents indicate a set of characters that can appear, in any sequence, in a password value
func (o LookupDomainsPasswordPolicyResultOutput) AllowedChars() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.AllowedChars }).(pulumi.StringOutput)
}

func (o LookupDomainsPasswordPolicyResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

func (o LookupDomainsPasswordPolicyResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsPasswordPolicyResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsPasswordPolicyResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// List of password policy rules that have values set. This map of stringKey:stringValue pairs can be used to aid users while setting/resetting password
func (o LookupDomainsPasswordPolicyResultOutput) ConfiguredPasswordPolicyRules() GetDomainsPasswordPolicyConfiguredPasswordPolicyRuleArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []GetDomainsPasswordPolicyConfiguredPasswordPolicyRule {
		return v.ConfiguredPasswordPolicyRules
	}).(GetDomainsPasswordPolicyConfiguredPasswordPolicyRuleArrayOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsPasswordPolicyResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// A String that describes the password policy
func (o LookupDomainsPasswordPolicyResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.Description }).(pulumi.StringOutput)
}

// A delimiter used to separate characters in the dictionary file
func (o LookupDomainsPasswordPolicyResultOutput) DictionaryDelimiter() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.DictionaryDelimiter }).(pulumi.StringOutput)
}

// A Reference value that contains the URI of a dictionary of words not allowed to appear within a password value
func (o LookupDomainsPasswordPolicyResultOutput) DictionaryLocation() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.DictionaryLocation }).(pulumi.StringOutput)
}

// Indicates whether the password can match a dictionary word
func (o LookupDomainsPasswordPolicyResultOutput) DictionaryWordDisallowed() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.DictionaryWordDisallowed }).(pulumi.BoolOutput)
}

// A String value whose contents indicate a set of characters that cannot appear, in any sequence, in a password value
func (o LookupDomainsPasswordPolicyResultOutput) DisallowedChars() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.DisallowedChars }).(pulumi.StringOutput)
}

// A String value whose contents indicate a set of substrings that cannot appear, in any sequence, in a password value
func (o LookupDomainsPasswordPolicyResultOutput) DisallowedSubstrings() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []string { return v.DisallowedSubstrings }).(pulumi.StringArrayOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsPasswordPolicyResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
func (o LookupDomainsPasswordPolicyResultOutput) ExternalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.ExternalId }).(pulumi.StringOutput)
}

// Indicates a sequence of characters that match the user's first name of given name cannot be the password. Password validation against policy will be ignored if length of first name is less than or equal to 3 characters.
func (o LookupDomainsPasswordPolicyResultOutput) FirstNameDisallowed() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.FirstNameDisallowed }).(pulumi.BoolOutput)
}

// Indicates whether all of the users should be forced to reset their password on the next login (to comply with new password policy changes)
func (o LookupDomainsPasswordPolicyResultOutput) ForcePasswordReset() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.ForcePasswordReset }).(pulumi.BoolOutput)
}

// A list of groups that the password policy belongs to.
func (o LookupDomainsPasswordPolicyResultOutput) Groups() GetDomainsPasswordPolicyGroupArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []GetDomainsPasswordPolicyGroup { return v.Groups }).(GetDomainsPasswordPolicyGroupArrayOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsPasswordPolicyResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsPasswordPolicyResultOutput) IdcsCreatedBies() GetDomainsPasswordPolicyIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []GetDomainsPasswordPolicyIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsPasswordPolicyIdcsCreatedByArrayOutput)
}

func (o LookupDomainsPasswordPolicyResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsPasswordPolicyResultOutput) IdcsLastModifiedBies() GetDomainsPasswordPolicyIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []GetDomainsPasswordPolicyIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsPasswordPolicyIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsPasswordPolicyResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsPasswordPolicyResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// Indicates a sequence of characters that match the user's last name of given name cannot be the password. Password validation against policy will be ignored if length of last name is less than or equal to 3 characters.
func (o LookupDomainsPasswordPolicyResultOutput) LastNameDisallowed() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.LastNameDisallowed }).(pulumi.BoolOutput)
}

// The time period in minutes to lock out a user account when the threshold of invalid login attempts is reached. The available range is from 5 through 1440 minutes (24 hours).
func (o LookupDomainsPasswordPolicyResultOutput) LockoutDuration() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.LockoutDuration }).(pulumi.IntOutput)
}

// An integer that represents the maximum number of failed logins before an account is locked
func (o LookupDomainsPasswordPolicyResultOutput) MaxIncorrectAttempts() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MaxIncorrectAttempts }).(pulumi.IntOutput)
}

// The maximum password length (in characters). A value of 0 or no value indicates no maximum length restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MaxLength() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MaxLength }).(pulumi.IntOutput)
}

// The maximum number of repeated characters allowed in a password.  A value of 0 or no value indicates no such restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MaxRepeatedChars() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MaxRepeatedChars }).(pulumi.IntOutput)
}

// The maximum number of special characters in a password.  A value of 0 or no value indicates no maximum special characters restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MaxSpecialChars() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MaxSpecialChars }).(pulumi.IntOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsPasswordPolicyResultOutput) Metas() GetDomainsPasswordPolicyMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []GetDomainsPasswordPolicyMeta { return v.Metas }).(GetDomainsPasswordPolicyMetaArrayOutput)
}

// The minimum number of a combination of alphabetic and numeric characters in a password.  A value of 0 or no value indicates no minimum alphanumeric character restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinAlphaNumerals() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinAlphaNumerals }).(pulumi.IntOutput)
}

// The minimum number of alphabetic characters in a password.  A value of 0 or no value indicates no minimum alphas restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinAlphas() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinAlphas }).(pulumi.IntOutput)
}

// The minimum password length (in characters). A value of 0 or no value indicates no minimum length restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinLength() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinLength }).(pulumi.IntOutput)
}

// The minimum number of lowercase alphabetic characters in a password.  A value of 0 or no value indicates no minimum lowercase restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinLowerCase() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinLowerCase }).(pulumi.IntOutput)
}

// The minimum number of numeric characters in a password.  A value of 0 or no value indicates no minimum numeric character restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinNumerals() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinNumerals }).(pulumi.IntOutput)
}

// Minimum time after which the user can resubmit the reset password request
func (o LookupDomainsPasswordPolicyResultOutput) MinPasswordAge() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinPasswordAge }).(pulumi.IntOutput)
}

// The minimum number of special characters in a password. A value of 0 or no value indicates no minimum special characters restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinSpecialChars() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinSpecialChars }).(pulumi.IntOutput)
}

// The minimum number of unique characters in a password.  A value of 0 or no value indicates no minimum unique characters restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinUniqueChars() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinUniqueChars }).(pulumi.IntOutput)
}

// The minimum number of uppercase alphabetic characters in a password. A value of 0 or no value indicates no minimum uppercase restriction.
func (o LookupDomainsPasswordPolicyResultOutput) MinUpperCase() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.MinUpperCase }).(pulumi.IntOutput)
}

// A String that is the name of the policy to display to the user. This is the only mandatory attribute for a password policy.
func (o LookupDomainsPasswordPolicyResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.Name }).(pulumi.StringOutput)
}

// The number of passwords that will be kept in history that may not be used as a password
func (o LookupDomainsPasswordPolicyResultOutput) NumPasswordsInHistory() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.NumPasswordsInHistory }).(pulumi.IntOutput)
}

// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
func (o LookupDomainsPasswordPolicyResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.Ocid }).(pulumi.StringOutput)
}

// An integer indicating the number of days before which the user should be warned about password expiry.
func (o LookupDomainsPasswordPolicyResultOutput) PasswordExpireWarning() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.PasswordExpireWarning }).(pulumi.IntOutput)
}

// The number of days after which the password expires automatically
func (o LookupDomainsPasswordPolicyResultOutput) PasswordExpiresAfter() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.PasswordExpiresAfter }).(pulumi.IntOutput)
}

func (o LookupDomainsPasswordPolicyResultOutput) PasswordPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.PasswordPolicyId }).(pulumi.StringOutput)
}

// Indicates whether the password policy is configured as Simple, Standard, or Custom.
func (o LookupDomainsPasswordPolicyResultOutput) PasswordStrength() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.PasswordStrength }).(pulumi.StringOutput)
}

// Password policy priority
func (o LookupDomainsPasswordPolicyResultOutput) Priority() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) int { return v.Priority }).(pulumi.IntOutput)
}

// A String value whose contents indicate a set of characters that must appear, in any sequence, in a password value
func (o LookupDomainsPasswordPolicyResultOutput) RequiredChars() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.RequiredChars }).(pulumi.StringOutput)
}

func (o LookupDomainsPasswordPolicyResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsPasswordPolicyResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// Indicates that the password must begin with an alphabetic character
func (o LookupDomainsPasswordPolicyResultOutput) StartsWithAlphabet() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.StartsWithAlphabet }).(pulumi.BoolOutput)
}

// A list of tags on this resource.
func (o LookupDomainsPasswordPolicyResultOutput) Tags() GetDomainsPasswordPolicyTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) []GetDomainsPasswordPolicyTag { return v.Tags }).(GetDomainsPasswordPolicyTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsPasswordPolicyResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// Indicates a sequence of characters that match the username cannot be the password. Password validation against policy will be ignored if length of user name is less than or equal to 3 characters.
func (o LookupDomainsPasswordPolicyResultOutput) UserNameDisallowed() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsPasswordPolicyResult) bool { return v.UserNameDisallowed }).(pulumi.BoolOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsPasswordPolicyResultOutput{})
}