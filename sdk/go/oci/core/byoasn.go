// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Byoasn resource in Oracle Cloud Infrastructure Core service.
//
// # Creates a BYOASN Resource
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.NewByoasn(ctx, "test_byoasn", &core.ByoasnArgs{
//				Asn:           pulumi.Any(byoasnAsn),
//				CompartmentId: pulumi.Any(compartmentId),
//				DisplayName:   pulumi.Any(byoasnDisplayName),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
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
// Byoasns can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/byoasn:Byoasn test_byoasn "id"
// ```
type Byoasn struct {
	pulumi.CustomResourceState

	// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
	Asn pulumi.StringOutput `pulumi:"asn"`
	// The BYOIP Ranges that has the `Byoasn` as origin.
	ByoipRanges ByoasnByoipRangeArrayOutput `pulumi:"byoipRanges"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOASN Resource.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The `Byoasn` resource's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the `Byoasn` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the `Byoasn` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The date and time the `Byoasn` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeValidated pulumi.StringOutput `pulumi:"timeValidated"`
	// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a Byoasn](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOASN.htm) for details.
	ValidationToken pulumi.StringOutput `pulumi:"validationToken"`
}

// NewByoasn registers a new resource with the given unique name, arguments, and options.
func NewByoasn(ctx *pulumi.Context,
	name string, args *ByoasnArgs, opts ...pulumi.ResourceOption) (*Byoasn, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Asn == nil {
		return nil, errors.New("invalid value for required argument 'Asn'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Byoasn
	err := ctx.RegisterResource("oci:Core/byoasn:Byoasn", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetByoasn gets an existing Byoasn resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetByoasn(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ByoasnState, opts ...pulumi.ResourceOption) (*Byoasn, error) {
	var resource Byoasn
	err := ctx.ReadResource("oci:Core/byoasn:Byoasn", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Byoasn resources.
type byoasnState struct {
	// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
	Asn *string `pulumi:"asn"`
	// The BYOIP Ranges that has the `Byoasn` as origin.
	ByoipRanges []ByoasnByoipRange `pulumi:"byoipRanges"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOASN Resource.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The `Byoasn` resource's current state.
	State *string `pulumi:"state"`
	// The date and time the `Byoasn` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the `Byoasn` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The date and time the `Byoasn` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeValidated *string `pulumi:"timeValidated"`
	// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a Byoasn](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOASN.htm) for details.
	ValidationToken *string `pulumi:"validationToken"`
}

type ByoasnState struct {
	// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
	Asn pulumi.StringPtrInput
	// The BYOIP Ranges that has the `Byoasn` as origin.
	ByoipRanges ByoasnByoipRangeArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOASN Resource.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The `Byoasn` resource's current state.
	State pulumi.StringPtrInput
	// The date and time the `Byoasn` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time the `Byoasn` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringPtrInput
	// The date and time the `Byoasn` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeValidated pulumi.StringPtrInput
	// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a Byoasn](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOASN.htm) for details.
	ValidationToken pulumi.StringPtrInput
}

func (ByoasnState) ElementType() reflect.Type {
	return reflect.TypeOf((*byoasnState)(nil)).Elem()
}

type byoasnArgs struct {
	// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
	Asn string `pulumi:"asn"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOASN Resource.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a Byoasn resource.
type ByoasnArgs struct {
	// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
	Asn pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOASN Resource.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (ByoasnArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*byoasnArgs)(nil)).Elem()
}

type ByoasnInput interface {
	pulumi.Input

	ToByoasnOutput() ByoasnOutput
	ToByoasnOutputWithContext(ctx context.Context) ByoasnOutput
}

func (*Byoasn) ElementType() reflect.Type {
	return reflect.TypeOf((**Byoasn)(nil)).Elem()
}

func (i *Byoasn) ToByoasnOutput() ByoasnOutput {
	return i.ToByoasnOutputWithContext(context.Background())
}

func (i *Byoasn) ToByoasnOutputWithContext(ctx context.Context) ByoasnOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ByoasnOutput)
}

// ByoasnArrayInput is an input type that accepts ByoasnArray and ByoasnArrayOutput values.
// You can construct a concrete instance of `ByoasnArrayInput` via:
//
//	ByoasnArray{ ByoasnArgs{...} }
type ByoasnArrayInput interface {
	pulumi.Input

	ToByoasnArrayOutput() ByoasnArrayOutput
	ToByoasnArrayOutputWithContext(context.Context) ByoasnArrayOutput
}

type ByoasnArray []ByoasnInput

func (ByoasnArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Byoasn)(nil)).Elem()
}

func (i ByoasnArray) ToByoasnArrayOutput() ByoasnArrayOutput {
	return i.ToByoasnArrayOutputWithContext(context.Background())
}

func (i ByoasnArray) ToByoasnArrayOutputWithContext(ctx context.Context) ByoasnArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ByoasnArrayOutput)
}

// ByoasnMapInput is an input type that accepts ByoasnMap and ByoasnMapOutput values.
// You can construct a concrete instance of `ByoasnMapInput` via:
//
//	ByoasnMap{ "key": ByoasnArgs{...} }
type ByoasnMapInput interface {
	pulumi.Input

	ToByoasnMapOutput() ByoasnMapOutput
	ToByoasnMapOutputWithContext(context.Context) ByoasnMapOutput
}

type ByoasnMap map[string]ByoasnInput

func (ByoasnMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Byoasn)(nil)).Elem()
}

func (i ByoasnMap) ToByoasnMapOutput() ByoasnMapOutput {
	return i.ToByoasnMapOutputWithContext(context.Background())
}

func (i ByoasnMap) ToByoasnMapOutputWithContext(ctx context.Context) ByoasnMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ByoasnMapOutput)
}

type ByoasnOutput struct{ *pulumi.OutputState }

func (ByoasnOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Byoasn)(nil)).Elem()
}

func (o ByoasnOutput) ToByoasnOutput() ByoasnOutput {
	return o
}

func (o ByoasnOutput) ToByoasnOutputWithContext(ctx context.Context) ByoasnOutput {
	return o
}

// The Autonomous System Number (ASN) you are importing to the Oracle cloud.
func (o ByoasnOutput) Asn() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.Asn }).(pulumi.StringOutput)
}

// The BYOIP Ranges that has the `Byoasn` as origin.
func (o ByoasnOutput) ByoipRanges() ByoasnByoipRangeArrayOutput {
	return o.ApplyT(func(v *Byoasn) ByoasnByoipRangeArrayOutput { return v.ByoipRanges }).(ByoasnByoipRangeArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOASN Resource.
func (o ByoasnOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o ByoasnOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o ByoasnOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ByoasnOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The `Byoasn` resource's current state.
func (o ByoasnOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the `Byoasn` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ByoasnOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the `Byoasn` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ByoasnOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The date and time the `Byoasn` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ByoasnOutput) TimeValidated() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.TimeValidated }).(pulumi.StringOutput)
}

// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a Byoasn](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOASN.htm) for details.
func (o ByoasnOutput) ValidationToken() pulumi.StringOutput {
	return o.ApplyT(func(v *Byoasn) pulumi.StringOutput { return v.ValidationToken }).(pulumi.StringOutput)
}

type ByoasnArrayOutput struct{ *pulumi.OutputState }

func (ByoasnArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Byoasn)(nil)).Elem()
}

func (o ByoasnArrayOutput) ToByoasnArrayOutput() ByoasnArrayOutput {
	return o
}

func (o ByoasnArrayOutput) ToByoasnArrayOutputWithContext(ctx context.Context) ByoasnArrayOutput {
	return o
}

func (o ByoasnArrayOutput) Index(i pulumi.IntInput) ByoasnOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Byoasn {
		return vs[0].([]*Byoasn)[vs[1].(int)]
	}).(ByoasnOutput)
}

type ByoasnMapOutput struct{ *pulumi.OutputState }

func (ByoasnMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Byoasn)(nil)).Elem()
}

func (o ByoasnMapOutput) ToByoasnMapOutput() ByoasnMapOutput {
	return o
}

func (o ByoasnMapOutput) ToByoasnMapOutputWithContext(ctx context.Context) ByoasnMapOutput {
	return o
}

func (o ByoasnMapOutput) MapIndex(k pulumi.StringInput) ByoasnOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Byoasn {
		return vs[0].(map[string]*Byoasn)[vs[1].(string)]
	}).(ByoasnOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ByoasnInput)(nil)).Elem(), &Byoasn{})
	pulumi.RegisterInputType(reflect.TypeOf((*ByoasnArrayInput)(nil)).Elem(), ByoasnArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ByoasnMapInput)(nil)).Elem(), ByoasnMap{})
	pulumi.RegisterOutputType(ByoasnOutput{})
	pulumi.RegisterOutputType(ByoasnArrayOutput{})
	pulumi.RegisterOutputType(ByoasnMapOutput{})
}
