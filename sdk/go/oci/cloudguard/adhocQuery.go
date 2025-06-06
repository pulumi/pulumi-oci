// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Adhoc Query resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a AdhocQuery resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudguard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudguard.NewAdhocQuery(ctx, "test_adhoc_query", &cloudguard.AdhocQueryArgs{
//				AdhocQueryDetails: &cloudguard.AdhocQueryAdhocQueryDetailsArgs{
//					AdhocQueryResources: cloudguard.AdhocQueryAdhocQueryDetailsAdhocQueryResourceArray{
//						&cloudguard.AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs{
//							Region:       pulumi.Any(adhocQueryAdhocQueryDetailsAdhocQueryResourcesRegion),
//							ResourceIds:  pulumi.Any(adhocQueryAdhocQueryDetailsAdhocQueryResourcesResourceIds),
//							ResourceType: pulumi.Any(adhocQueryAdhocQueryDetailsAdhocQueryResourcesResourceType),
//						},
//					},
//					Query: pulumi.Any(adhocQueryAdhocQueryDetailsQuery),
//				},
//				CompartmentId: pulumi.Any(compartmentId),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// AdhocQueries can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudGuard/adhocQuery:AdhocQuery test_adhoc_query "id"
// ```
type AdhocQuery struct {
	pulumi.CustomResourceState

	// Detailed information about the adhoc query.
	AdhocQueryDetails AdhocQueryAdhocQueryDetailsOutput `pulumi:"adhocQueryDetails"`
	// Instance level status for each region
	AdhocQueryRegionalDetails AdhocQueryAdhocQueryRegionalDetailArrayOutput `pulumi:"adhocQueryRegionalDetails"`
	// Compartment OCID of adhoc query
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// Error message to show on UI in case of failure
	ErrorMessage pulumi.StringOutput `pulumi:"errorMessage"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The current lifecycle state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// Status of the adhoc query
	Status pulumi.StringOutput `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the adhoc query was created. Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the adhoc query was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewAdhocQuery registers a new resource with the given unique name, arguments, and options.
func NewAdhocQuery(ctx *pulumi.Context,
	name string, args *AdhocQueryArgs, opts ...pulumi.ResourceOption) (*AdhocQuery, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AdhocQueryDetails == nil {
		return nil, errors.New("invalid value for required argument 'AdhocQueryDetails'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource AdhocQuery
	err := ctx.RegisterResource("oci:CloudGuard/adhocQuery:AdhocQuery", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAdhocQuery gets an existing AdhocQuery resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAdhocQuery(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AdhocQueryState, opts ...pulumi.ResourceOption) (*AdhocQuery, error) {
	var resource AdhocQuery
	err := ctx.ReadResource("oci:CloudGuard/adhocQuery:AdhocQuery", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AdhocQuery resources.
type adhocQueryState struct {
	// Detailed information about the adhoc query.
	AdhocQueryDetails *AdhocQueryAdhocQueryDetails `pulumi:"adhocQueryDetails"`
	// Instance level status for each region
	AdhocQueryRegionalDetails []AdhocQueryAdhocQueryRegionalDetail `pulumi:"adhocQueryRegionalDetails"`
	// Compartment OCID of adhoc query
	CompartmentId *string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Error message to show on UI in case of failure
	ErrorMessage *string `pulumi:"errorMessage"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The current lifecycle state of the resource.
	State *string `pulumi:"state"`
	// Status of the adhoc query
	Status *string `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the adhoc query was created. Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the adhoc query was updated. Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type AdhocQueryState struct {
	// Detailed information about the adhoc query.
	AdhocQueryDetails AdhocQueryAdhocQueryDetailsPtrInput
	// Instance level status for each region
	AdhocQueryRegionalDetails AdhocQueryAdhocQueryRegionalDetailArrayInput
	// Compartment OCID of adhoc query
	CompartmentId pulumi.StringPtrInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// Error message to show on UI in case of failure
	ErrorMessage pulumi.StringPtrInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The current lifecycle state of the resource.
	State pulumi.StringPtrInput
	// Status of the adhoc query
	Status pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time the adhoc query was created. Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the adhoc query was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (AdhocQueryState) ElementType() reflect.Type {
	return reflect.TypeOf((*adhocQueryState)(nil)).Elem()
}

type adhocQueryArgs struct {
	// Detailed information about the adhoc query.
	AdhocQueryDetails AdhocQueryAdhocQueryDetails `pulumi:"adhocQueryDetails"`
	// Compartment OCID of adhoc query
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a AdhocQuery resource.
type AdhocQueryArgs struct {
	// Detailed information about the adhoc query.
	AdhocQueryDetails AdhocQueryAdhocQueryDetailsInput
	// Compartment OCID of adhoc query
	CompartmentId pulumi.StringInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (AdhocQueryArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*adhocQueryArgs)(nil)).Elem()
}

type AdhocQueryInput interface {
	pulumi.Input

	ToAdhocQueryOutput() AdhocQueryOutput
	ToAdhocQueryOutputWithContext(ctx context.Context) AdhocQueryOutput
}

func (*AdhocQuery) ElementType() reflect.Type {
	return reflect.TypeOf((**AdhocQuery)(nil)).Elem()
}

func (i *AdhocQuery) ToAdhocQueryOutput() AdhocQueryOutput {
	return i.ToAdhocQueryOutputWithContext(context.Background())
}

func (i *AdhocQuery) ToAdhocQueryOutputWithContext(ctx context.Context) AdhocQueryOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AdhocQueryOutput)
}

// AdhocQueryArrayInput is an input type that accepts AdhocQueryArray and AdhocQueryArrayOutput values.
// You can construct a concrete instance of `AdhocQueryArrayInput` via:
//
//	AdhocQueryArray{ AdhocQueryArgs{...} }
type AdhocQueryArrayInput interface {
	pulumi.Input

	ToAdhocQueryArrayOutput() AdhocQueryArrayOutput
	ToAdhocQueryArrayOutputWithContext(context.Context) AdhocQueryArrayOutput
}

type AdhocQueryArray []AdhocQueryInput

func (AdhocQueryArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AdhocQuery)(nil)).Elem()
}

func (i AdhocQueryArray) ToAdhocQueryArrayOutput() AdhocQueryArrayOutput {
	return i.ToAdhocQueryArrayOutputWithContext(context.Background())
}

func (i AdhocQueryArray) ToAdhocQueryArrayOutputWithContext(ctx context.Context) AdhocQueryArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AdhocQueryArrayOutput)
}

// AdhocQueryMapInput is an input type that accepts AdhocQueryMap and AdhocQueryMapOutput values.
// You can construct a concrete instance of `AdhocQueryMapInput` via:
//
//	AdhocQueryMap{ "key": AdhocQueryArgs{...} }
type AdhocQueryMapInput interface {
	pulumi.Input

	ToAdhocQueryMapOutput() AdhocQueryMapOutput
	ToAdhocQueryMapOutputWithContext(context.Context) AdhocQueryMapOutput
}

type AdhocQueryMap map[string]AdhocQueryInput

func (AdhocQueryMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AdhocQuery)(nil)).Elem()
}

func (i AdhocQueryMap) ToAdhocQueryMapOutput() AdhocQueryMapOutput {
	return i.ToAdhocQueryMapOutputWithContext(context.Background())
}

func (i AdhocQueryMap) ToAdhocQueryMapOutputWithContext(ctx context.Context) AdhocQueryMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AdhocQueryMapOutput)
}

type AdhocQueryOutput struct{ *pulumi.OutputState }

func (AdhocQueryOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AdhocQuery)(nil)).Elem()
}

func (o AdhocQueryOutput) ToAdhocQueryOutput() AdhocQueryOutput {
	return o
}

func (o AdhocQueryOutput) ToAdhocQueryOutputWithContext(ctx context.Context) AdhocQueryOutput {
	return o
}

// Detailed information about the adhoc query.
func (o AdhocQueryOutput) AdhocQueryDetails() AdhocQueryAdhocQueryDetailsOutput {
	return o.ApplyT(func(v *AdhocQuery) AdhocQueryAdhocQueryDetailsOutput { return v.AdhocQueryDetails }).(AdhocQueryAdhocQueryDetailsOutput)
}

// Instance level status for each region
func (o AdhocQueryOutput) AdhocQueryRegionalDetails() AdhocQueryAdhocQueryRegionalDetailArrayOutput {
	return o.ApplyT(func(v *AdhocQuery) AdhocQueryAdhocQueryRegionalDetailArrayOutput { return v.AdhocQueryRegionalDetails }).(AdhocQueryAdhocQueryRegionalDetailArrayOutput)
}

// Compartment OCID of adhoc query
func (o AdhocQueryOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o AdhocQueryOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Error message to show on UI in case of failure
func (o AdhocQueryOutput) ErrorMessage() pulumi.StringOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringOutput { return v.ErrorMessage }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
//
// Avoid entering confidential information.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o AdhocQueryOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The current lifecycle state of the resource.
func (o AdhocQueryOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Status of the adhoc query
func (o AdhocQueryOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o AdhocQueryOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the adhoc query was created. Format defined by RFC3339.
func (o AdhocQueryOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the adhoc query was updated. Format defined by RFC3339.
func (o AdhocQueryOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *AdhocQuery) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type AdhocQueryArrayOutput struct{ *pulumi.OutputState }

func (AdhocQueryArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AdhocQuery)(nil)).Elem()
}

func (o AdhocQueryArrayOutput) ToAdhocQueryArrayOutput() AdhocQueryArrayOutput {
	return o
}

func (o AdhocQueryArrayOutput) ToAdhocQueryArrayOutputWithContext(ctx context.Context) AdhocQueryArrayOutput {
	return o
}

func (o AdhocQueryArrayOutput) Index(i pulumi.IntInput) AdhocQueryOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AdhocQuery {
		return vs[0].([]*AdhocQuery)[vs[1].(int)]
	}).(AdhocQueryOutput)
}

type AdhocQueryMapOutput struct{ *pulumi.OutputState }

func (AdhocQueryMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AdhocQuery)(nil)).Elem()
}

func (o AdhocQueryMapOutput) ToAdhocQueryMapOutput() AdhocQueryMapOutput {
	return o
}

func (o AdhocQueryMapOutput) ToAdhocQueryMapOutputWithContext(ctx context.Context) AdhocQueryMapOutput {
	return o
}

func (o AdhocQueryMapOutput) MapIndex(k pulumi.StringInput) AdhocQueryOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AdhocQuery {
		return vs[0].(map[string]*AdhocQuery)[vs[1].(string)]
	}).(AdhocQueryOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AdhocQueryInput)(nil)).Elem(), &AdhocQuery{})
	pulumi.RegisterInputType(reflect.TypeOf((*AdhocQueryArrayInput)(nil)).Elem(), AdhocQueryArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AdhocQueryMapInput)(nil)).Elem(), AdhocQueryMap{})
	pulumi.RegisterOutputType(AdhocQueryOutput{})
	pulumi.RegisterOutputType(AdhocQueryArrayOutput{})
	pulumi.RegisterOutputType(AdhocQueryMapOutput{})
}
