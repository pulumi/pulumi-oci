// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the My Auth Token resource in Oracle Cloud Infrastructure Identity Domains service.
//
// # Add user's auth token
//
// ## Import
//
// MyAuthTokens can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Identity/domainsMyAuthToken:DomainsMyAuthToken test_my_auth_token "idcsEndpoint/{idcsEndpoint}/myAuthTokens/{myAuthTokenId}"
//
// ```
type DomainsMyAuthToken struct {
	pulumi.CustomResourceState

	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrOutput `pulumi:"authorization"`
	// (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid pulumi.StringOutput `pulumi:"compartmentOcid"`
	// (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress pulumi.BoolOutput `pulumi:"deleteInProgress"`
	// Description
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid pulumi.StringOutput `pulumi:"domainOcid"`
	// User credential expires on
	ExpiresOn pulumi.StringOutput `pulumi:"expiresOn"`
	// (Updatable) The User or App who created the Resource
	IdcsCreatedBies DomainsMyAuthTokenIdcsCreatedByArrayOutput `pulumi:"idcsCreatedBies"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringOutput `pulumi:"idcsEndpoint"`
	// (Updatable) The User or App who modified the Resource
	IdcsLastModifiedBies DomainsMyAuthTokenIdcsLastModifiedByArrayOutput `pulumi:"idcsLastModifiedBies"`
	// (Updatable) The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease pulumi.StringOutput `pulumi:"idcsLastUpgradedInRelease"`
	// (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations pulumi.StringArrayOutput `pulumi:"idcsPreventedOperations"`
	// (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas DomainsMyAuthTokenMetaArrayOutput `pulumi:"metas"`
	// User's ocid
	Ocid pulumi.StringOutput `pulumi:"ocid"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrOutput `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas pulumi.StringArrayOutput `pulumi:"schemas"`
	// User credential status
	Status pulumi.StringOutput `pulumi:"status"`
	// A list of tags on this resource.
	Tags DomainsMyAuthTokenTagArrayOutput `pulumi:"tags"`
	// (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid pulumi.StringOutput `pulumi:"tenancyOcid"`
	// User linked to auth token
	User DomainsMyAuthTokenUserOutput `pulumi:"user"`
}

// NewDomainsMyAuthToken registers a new resource with the given unique name, arguments, and options.
func NewDomainsMyAuthToken(ctx *pulumi.Context,
	name string, args *DomainsMyAuthTokenArgs, opts ...pulumi.ResourceOption) (*DomainsMyAuthToken, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.IdcsEndpoint == nil {
		return nil, errors.New("invalid value for required argument 'IdcsEndpoint'")
	}
	if args.Schemas == nil {
		return nil, errors.New("invalid value for required argument 'Schemas'")
	}
	var resource DomainsMyAuthToken
	err := ctx.RegisterResource("oci:Identity/domainsMyAuthToken:DomainsMyAuthToken", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDomainsMyAuthToken gets an existing DomainsMyAuthToken resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDomainsMyAuthToken(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DomainsMyAuthTokenState, opts ...pulumi.ResourceOption) (*DomainsMyAuthToken, error) {
	var resource DomainsMyAuthToken
	err := ctx.ReadResource("oci:Identity/domainsMyAuthToken:DomainsMyAuthToken", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DomainsMyAuthToken resources.
type domainsMyAuthTokenState struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid *string `pulumi:"compartmentOcid"`
	// (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress *bool `pulumi:"deleteInProgress"`
	// Description
	Description *string `pulumi:"description"`
	// (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid *string `pulumi:"domainOcid"`
	// User credential expires on
	ExpiresOn *string `pulumi:"expiresOn"`
	// (Updatable) The User or App who created the Resource
	IdcsCreatedBies []DomainsMyAuthTokenIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	// The basic endpoint for the identity domain
	IdcsEndpoint *string `pulumi:"idcsEndpoint"`
	// (Updatable) The User or App who modified the Resource
	IdcsLastModifiedBies []DomainsMyAuthTokenIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// (Updatable) The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease *string `pulumi:"idcsLastUpgradedInRelease"`
	// (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []DomainsMyAuthTokenMeta `pulumi:"metas"`
	// User's ocid
	Ocid *string `pulumi:"ocid"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// User credential status
	Status *string `pulumi:"status"`
	// A list of tags on this resource.
	Tags []DomainsMyAuthTokenTag `pulumi:"tags"`
	// (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid *string `pulumi:"tenancyOcid"`
	// User linked to auth token
	User *DomainsMyAuthTokenUser `pulumi:"user"`
}

type DomainsMyAuthTokenState struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput
	// (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid pulumi.StringPtrInput
	// (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress pulumi.BoolPtrInput
	// Description
	Description pulumi.StringPtrInput
	// (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid pulumi.StringPtrInput
	// User credential expires on
	ExpiresOn pulumi.StringPtrInput
	// (Updatable) The User or App who created the Resource
	IdcsCreatedBies DomainsMyAuthTokenIdcsCreatedByArrayInput
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringPtrInput
	// (Updatable) The User or App who modified the Resource
	IdcsLastModifiedBies DomainsMyAuthTokenIdcsLastModifiedByArrayInput
	// (Updatable) The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease pulumi.StringPtrInput
	// (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations pulumi.StringArrayInput
	// (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas DomainsMyAuthTokenMetaArrayInput
	// User's ocid
	Ocid pulumi.StringPtrInput
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas pulumi.StringArrayInput
	// User credential status
	Status pulumi.StringPtrInput
	// A list of tags on this resource.
	Tags DomainsMyAuthTokenTagArrayInput
	// (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid pulumi.StringPtrInput
	// User linked to auth token
	User DomainsMyAuthTokenUserPtrInput
}

func (DomainsMyAuthTokenState) ElementType() reflect.Type {
	return reflect.TypeOf((*domainsMyAuthTokenState)(nil)).Elem()
}

type domainsMyAuthTokenArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// Description
	Description *string `pulumi:"description"`
	// User credential expires on
	ExpiresOn *string `pulumi:"expiresOn"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// User's ocid
	Ocid *string `pulumi:"ocid"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// User credential status
	Status *string `pulumi:"status"`
	// A list of tags on this resource.
	Tags []DomainsMyAuthTokenTag `pulumi:"tags"`
	// User linked to auth token
	User *DomainsMyAuthTokenUser `pulumi:"user"`
}

// The set of arguments for constructing a DomainsMyAuthToken resource.
type DomainsMyAuthTokenArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput
	// Description
	Description pulumi.StringPtrInput
	// User credential expires on
	ExpiresOn pulumi.StringPtrInput
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput
	// User's ocid
	Ocid pulumi.StringPtrInput
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas pulumi.StringArrayInput
	// User credential status
	Status pulumi.StringPtrInput
	// A list of tags on this resource.
	Tags DomainsMyAuthTokenTagArrayInput
	// User linked to auth token
	User DomainsMyAuthTokenUserPtrInput
}

func (DomainsMyAuthTokenArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*domainsMyAuthTokenArgs)(nil)).Elem()
}

type DomainsMyAuthTokenInput interface {
	pulumi.Input

	ToDomainsMyAuthTokenOutput() DomainsMyAuthTokenOutput
	ToDomainsMyAuthTokenOutputWithContext(ctx context.Context) DomainsMyAuthTokenOutput
}

func (*DomainsMyAuthToken) ElementType() reflect.Type {
	return reflect.TypeOf((**DomainsMyAuthToken)(nil)).Elem()
}

func (i *DomainsMyAuthToken) ToDomainsMyAuthTokenOutput() DomainsMyAuthTokenOutput {
	return i.ToDomainsMyAuthTokenOutputWithContext(context.Background())
}

func (i *DomainsMyAuthToken) ToDomainsMyAuthTokenOutputWithContext(ctx context.Context) DomainsMyAuthTokenOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DomainsMyAuthTokenOutput)
}

// DomainsMyAuthTokenArrayInput is an input type that accepts DomainsMyAuthTokenArray and DomainsMyAuthTokenArrayOutput values.
// You can construct a concrete instance of `DomainsMyAuthTokenArrayInput` via:
//
//	DomainsMyAuthTokenArray{ DomainsMyAuthTokenArgs{...} }
type DomainsMyAuthTokenArrayInput interface {
	pulumi.Input

	ToDomainsMyAuthTokenArrayOutput() DomainsMyAuthTokenArrayOutput
	ToDomainsMyAuthTokenArrayOutputWithContext(context.Context) DomainsMyAuthTokenArrayOutput
}

type DomainsMyAuthTokenArray []DomainsMyAuthTokenInput

func (DomainsMyAuthTokenArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DomainsMyAuthToken)(nil)).Elem()
}

func (i DomainsMyAuthTokenArray) ToDomainsMyAuthTokenArrayOutput() DomainsMyAuthTokenArrayOutput {
	return i.ToDomainsMyAuthTokenArrayOutputWithContext(context.Background())
}

func (i DomainsMyAuthTokenArray) ToDomainsMyAuthTokenArrayOutputWithContext(ctx context.Context) DomainsMyAuthTokenArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DomainsMyAuthTokenArrayOutput)
}

// DomainsMyAuthTokenMapInput is an input type that accepts DomainsMyAuthTokenMap and DomainsMyAuthTokenMapOutput values.
// You can construct a concrete instance of `DomainsMyAuthTokenMapInput` via:
//
//	DomainsMyAuthTokenMap{ "key": DomainsMyAuthTokenArgs{...} }
type DomainsMyAuthTokenMapInput interface {
	pulumi.Input

	ToDomainsMyAuthTokenMapOutput() DomainsMyAuthTokenMapOutput
	ToDomainsMyAuthTokenMapOutputWithContext(context.Context) DomainsMyAuthTokenMapOutput
}

type DomainsMyAuthTokenMap map[string]DomainsMyAuthTokenInput

func (DomainsMyAuthTokenMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DomainsMyAuthToken)(nil)).Elem()
}

func (i DomainsMyAuthTokenMap) ToDomainsMyAuthTokenMapOutput() DomainsMyAuthTokenMapOutput {
	return i.ToDomainsMyAuthTokenMapOutputWithContext(context.Background())
}

func (i DomainsMyAuthTokenMap) ToDomainsMyAuthTokenMapOutputWithContext(ctx context.Context) DomainsMyAuthTokenMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DomainsMyAuthTokenMapOutput)
}

type DomainsMyAuthTokenOutput struct{ *pulumi.OutputState }

func (DomainsMyAuthTokenOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DomainsMyAuthToken)(nil)).Elem()
}

func (o DomainsMyAuthTokenOutput) ToDomainsMyAuthTokenOutput() DomainsMyAuthTokenOutput {
	return o
}

func (o DomainsMyAuthTokenOutput) ToDomainsMyAuthTokenOutputWithContext(ctx context.Context) DomainsMyAuthTokenOutput {
	return o
}

// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
func (o DomainsMyAuthTokenOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringPtrOutput { return v.Authorization }).(pulumi.StringPtrOutput)
}

// (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o DomainsMyAuthTokenOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o DomainsMyAuthTokenOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.BoolOutput { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Description
func (o DomainsMyAuthTokenOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o DomainsMyAuthTokenOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.DomainOcid }).(pulumi.StringOutput)
}

// User credential expires on
func (o DomainsMyAuthTokenOutput) ExpiresOn() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.ExpiresOn }).(pulumi.StringOutput)
}

// (Updatable) The User or App who created the Resource
func (o DomainsMyAuthTokenOutput) IdcsCreatedBies() DomainsMyAuthTokenIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) DomainsMyAuthTokenIdcsCreatedByArrayOutput { return v.IdcsCreatedBies }).(DomainsMyAuthTokenIdcsCreatedByArrayOutput)
}

// The basic endpoint for the identity domain
func (o DomainsMyAuthTokenOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// (Updatable) The User or App who modified the Resource
func (o DomainsMyAuthTokenOutput) IdcsLastModifiedBies() DomainsMyAuthTokenIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) DomainsMyAuthTokenIdcsLastModifiedByArrayOutput {
		return v.IdcsLastModifiedBies
	}).(DomainsMyAuthTokenIdcsLastModifiedByArrayOutput)
}

// (Updatable) The release number when the resource was upgraded.
func (o DomainsMyAuthTokenOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o DomainsMyAuthTokenOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringArrayOutput { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o DomainsMyAuthTokenOutput) Metas() DomainsMyAuthTokenMetaArrayOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) DomainsMyAuthTokenMetaArrayOutput { return v.Metas }).(DomainsMyAuthTokenMetaArrayOutput)
}

// User's ocid
func (o DomainsMyAuthTokenOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.Ocid }).(pulumi.StringOutput)
}

// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
func (o DomainsMyAuthTokenOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringPtrOutput { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o DomainsMyAuthTokenOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringArrayOutput { return v.Schemas }).(pulumi.StringArrayOutput)
}

// User credential status
func (o DomainsMyAuthTokenOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// A list of tags on this resource.
func (o DomainsMyAuthTokenOutput) Tags() DomainsMyAuthTokenTagArrayOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) DomainsMyAuthTokenTagArrayOutput { return v.Tags }).(DomainsMyAuthTokenTagArrayOutput)
}

// (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o DomainsMyAuthTokenOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) pulumi.StringOutput { return v.TenancyOcid }).(pulumi.StringOutput)
}

// User linked to auth token
func (o DomainsMyAuthTokenOutput) User() DomainsMyAuthTokenUserOutput {
	return o.ApplyT(func(v *DomainsMyAuthToken) DomainsMyAuthTokenUserOutput { return v.User }).(DomainsMyAuthTokenUserOutput)
}

type DomainsMyAuthTokenArrayOutput struct{ *pulumi.OutputState }

func (DomainsMyAuthTokenArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DomainsMyAuthToken)(nil)).Elem()
}

func (o DomainsMyAuthTokenArrayOutput) ToDomainsMyAuthTokenArrayOutput() DomainsMyAuthTokenArrayOutput {
	return o
}

func (o DomainsMyAuthTokenArrayOutput) ToDomainsMyAuthTokenArrayOutputWithContext(ctx context.Context) DomainsMyAuthTokenArrayOutput {
	return o
}

func (o DomainsMyAuthTokenArrayOutput) Index(i pulumi.IntInput) DomainsMyAuthTokenOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DomainsMyAuthToken {
		return vs[0].([]*DomainsMyAuthToken)[vs[1].(int)]
	}).(DomainsMyAuthTokenOutput)
}

type DomainsMyAuthTokenMapOutput struct{ *pulumi.OutputState }

func (DomainsMyAuthTokenMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DomainsMyAuthToken)(nil)).Elem()
}

func (o DomainsMyAuthTokenMapOutput) ToDomainsMyAuthTokenMapOutput() DomainsMyAuthTokenMapOutput {
	return o
}

func (o DomainsMyAuthTokenMapOutput) ToDomainsMyAuthTokenMapOutputWithContext(ctx context.Context) DomainsMyAuthTokenMapOutput {
	return o
}

func (o DomainsMyAuthTokenMapOutput) MapIndex(k pulumi.StringInput) DomainsMyAuthTokenOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DomainsMyAuthToken {
		return vs[0].(map[string]*DomainsMyAuthToken)[vs[1].(string)]
	}).(DomainsMyAuthTokenOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DomainsMyAuthTokenInput)(nil)).Elem(), &DomainsMyAuthToken{})
	pulumi.RegisterInputType(reflect.TypeOf((*DomainsMyAuthTokenArrayInput)(nil)).Elem(), DomainsMyAuthTokenArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DomainsMyAuthTokenMapInput)(nil)).Elem(), DomainsMyAuthTokenMap{})
	pulumi.RegisterOutputType(DomainsMyAuthTokenOutput{})
	pulumi.RegisterOutputType(DomainsMyAuthTokenArrayOutput{})
	pulumi.RegisterOutputType(DomainsMyAuthTokenMapOutput{})
}