// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Namespace Lookups Update Data Management resource in Oracle Cloud Infrastructure Log Analytics service.
//
// Updates the lookup content. The csv file containing the content to be updated is passed in as binary data in the request.
type NamespaceLookupsUpdateDataManagement struct {
	pulumi.CustomResourceState

	// The character encoding of the uploaded file.
	CharEncoding pulumi.StringOutput `pulumi:"charEncoding"`
	// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
	Expect pulumi.StringOutput `pulumi:"expect"`
	// is force
	IsForce pulumi.BoolOutput `pulumi:"isForce"`
	// The name of the lookup to operate on.
	LookupName pulumi.StringOutput `pulumi:"lookupName"`
	// The Logging Analytics namespace used for the request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Namespace        pulumi.StringOutput `pulumi:"namespace"`
	UpdateLookupFile pulumi.StringOutput `pulumi:"updateLookupFile"`
}

// NewNamespaceLookupsUpdateDataManagement registers a new resource with the given unique name, arguments, and options.
func NewNamespaceLookupsUpdateDataManagement(ctx *pulumi.Context,
	name string, args *NamespaceLookupsUpdateDataManagementArgs, opts ...pulumi.ResourceOption) (*NamespaceLookupsUpdateDataManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.LookupName == nil {
		return nil, errors.New("invalid value for required argument 'LookupName'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	if args.UpdateLookupFile == nil {
		return nil, errors.New("invalid value for required argument 'UpdateLookupFile'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource NamespaceLookupsUpdateDataManagement
	err := ctx.RegisterResource("oci:LogAnalytics/namespaceLookupsUpdateDataManagement:NamespaceLookupsUpdateDataManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetNamespaceLookupsUpdateDataManagement gets an existing NamespaceLookupsUpdateDataManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetNamespaceLookupsUpdateDataManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *NamespaceLookupsUpdateDataManagementState, opts ...pulumi.ResourceOption) (*NamespaceLookupsUpdateDataManagement, error) {
	var resource NamespaceLookupsUpdateDataManagement
	err := ctx.ReadResource("oci:LogAnalytics/namespaceLookupsUpdateDataManagement:NamespaceLookupsUpdateDataManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering NamespaceLookupsUpdateDataManagement resources.
type namespaceLookupsUpdateDataManagementState struct {
	// The character encoding of the uploaded file.
	CharEncoding *string `pulumi:"charEncoding"`
	// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
	Expect *string `pulumi:"expect"`
	// is force
	IsForce *bool `pulumi:"isForce"`
	// The name of the lookup to operate on.
	LookupName *string `pulumi:"lookupName"`
	// The Logging Analytics namespace used for the request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Namespace        *string `pulumi:"namespace"`
	UpdateLookupFile *string `pulumi:"updateLookupFile"`
}

type NamespaceLookupsUpdateDataManagementState struct {
	// The character encoding of the uploaded file.
	CharEncoding pulumi.StringPtrInput
	// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
	Expect pulumi.StringPtrInput
	// is force
	IsForce pulumi.BoolPtrInput
	// The name of the lookup to operate on.
	LookupName pulumi.StringPtrInput
	// The Logging Analytics namespace used for the request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Namespace        pulumi.StringPtrInput
	UpdateLookupFile pulumi.StringPtrInput
}

func (NamespaceLookupsUpdateDataManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*namespaceLookupsUpdateDataManagementState)(nil)).Elem()
}

type namespaceLookupsUpdateDataManagementArgs struct {
	// The character encoding of the uploaded file.
	CharEncoding *string `pulumi:"charEncoding"`
	// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
	Expect *string `pulumi:"expect"`
	// is force
	IsForce *bool `pulumi:"isForce"`
	// The name of the lookup to operate on.
	LookupName string `pulumi:"lookupName"`
	// The Logging Analytics namespace used for the request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Namespace        string `pulumi:"namespace"`
	UpdateLookupFile string `pulumi:"updateLookupFile"`
}

// The set of arguments for constructing a NamespaceLookupsUpdateDataManagement resource.
type NamespaceLookupsUpdateDataManagementArgs struct {
	// The character encoding of the uploaded file.
	CharEncoding pulumi.StringPtrInput
	// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
	Expect pulumi.StringPtrInput
	// is force
	IsForce pulumi.BoolPtrInput
	// The name of the lookup to operate on.
	LookupName pulumi.StringInput
	// The Logging Analytics namespace used for the request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Namespace        pulumi.StringInput
	UpdateLookupFile pulumi.StringInput
}

func (NamespaceLookupsUpdateDataManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*namespaceLookupsUpdateDataManagementArgs)(nil)).Elem()
}

type NamespaceLookupsUpdateDataManagementInput interface {
	pulumi.Input

	ToNamespaceLookupsUpdateDataManagementOutput() NamespaceLookupsUpdateDataManagementOutput
	ToNamespaceLookupsUpdateDataManagementOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementOutput
}

func (*NamespaceLookupsUpdateDataManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**NamespaceLookupsUpdateDataManagement)(nil)).Elem()
}

func (i *NamespaceLookupsUpdateDataManagement) ToNamespaceLookupsUpdateDataManagementOutput() NamespaceLookupsUpdateDataManagementOutput {
	return i.ToNamespaceLookupsUpdateDataManagementOutputWithContext(context.Background())
}

func (i *NamespaceLookupsUpdateDataManagement) ToNamespaceLookupsUpdateDataManagementOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NamespaceLookupsUpdateDataManagementOutput)
}

// NamespaceLookupsUpdateDataManagementArrayInput is an input type that accepts NamespaceLookupsUpdateDataManagementArray and NamespaceLookupsUpdateDataManagementArrayOutput values.
// You can construct a concrete instance of `NamespaceLookupsUpdateDataManagementArrayInput` via:
//
//	NamespaceLookupsUpdateDataManagementArray{ NamespaceLookupsUpdateDataManagementArgs{...} }
type NamespaceLookupsUpdateDataManagementArrayInput interface {
	pulumi.Input

	ToNamespaceLookupsUpdateDataManagementArrayOutput() NamespaceLookupsUpdateDataManagementArrayOutput
	ToNamespaceLookupsUpdateDataManagementArrayOutputWithContext(context.Context) NamespaceLookupsUpdateDataManagementArrayOutput
}

type NamespaceLookupsUpdateDataManagementArray []NamespaceLookupsUpdateDataManagementInput

func (NamespaceLookupsUpdateDataManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NamespaceLookupsUpdateDataManagement)(nil)).Elem()
}

func (i NamespaceLookupsUpdateDataManagementArray) ToNamespaceLookupsUpdateDataManagementArrayOutput() NamespaceLookupsUpdateDataManagementArrayOutput {
	return i.ToNamespaceLookupsUpdateDataManagementArrayOutputWithContext(context.Background())
}

func (i NamespaceLookupsUpdateDataManagementArray) ToNamespaceLookupsUpdateDataManagementArrayOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NamespaceLookupsUpdateDataManagementArrayOutput)
}

// NamespaceLookupsUpdateDataManagementMapInput is an input type that accepts NamespaceLookupsUpdateDataManagementMap and NamespaceLookupsUpdateDataManagementMapOutput values.
// You can construct a concrete instance of `NamespaceLookupsUpdateDataManagementMapInput` via:
//
//	NamespaceLookupsUpdateDataManagementMap{ "key": NamespaceLookupsUpdateDataManagementArgs{...} }
type NamespaceLookupsUpdateDataManagementMapInput interface {
	pulumi.Input

	ToNamespaceLookupsUpdateDataManagementMapOutput() NamespaceLookupsUpdateDataManagementMapOutput
	ToNamespaceLookupsUpdateDataManagementMapOutputWithContext(context.Context) NamespaceLookupsUpdateDataManagementMapOutput
}

type NamespaceLookupsUpdateDataManagementMap map[string]NamespaceLookupsUpdateDataManagementInput

func (NamespaceLookupsUpdateDataManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NamespaceLookupsUpdateDataManagement)(nil)).Elem()
}

func (i NamespaceLookupsUpdateDataManagementMap) ToNamespaceLookupsUpdateDataManagementMapOutput() NamespaceLookupsUpdateDataManagementMapOutput {
	return i.ToNamespaceLookupsUpdateDataManagementMapOutputWithContext(context.Background())
}

func (i NamespaceLookupsUpdateDataManagementMap) ToNamespaceLookupsUpdateDataManagementMapOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(NamespaceLookupsUpdateDataManagementMapOutput)
}

type NamespaceLookupsUpdateDataManagementOutput struct{ *pulumi.OutputState }

func (NamespaceLookupsUpdateDataManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**NamespaceLookupsUpdateDataManagement)(nil)).Elem()
}

func (o NamespaceLookupsUpdateDataManagementOutput) ToNamespaceLookupsUpdateDataManagementOutput() NamespaceLookupsUpdateDataManagementOutput {
	return o
}

func (o NamespaceLookupsUpdateDataManagementOutput) ToNamespaceLookupsUpdateDataManagementOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementOutput {
	return o
}

// The character encoding of the uploaded file.
func (o NamespaceLookupsUpdateDataManagementOutput) CharEncoding() pulumi.StringOutput {
	return o.ApplyT(func(v *NamespaceLookupsUpdateDataManagement) pulumi.StringOutput { return v.CharEncoding }).(pulumi.StringOutput)
}

// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
func (o NamespaceLookupsUpdateDataManagementOutput) Expect() pulumi.StringOutput {
	return o.ApplyT(func(v *NamespaceLookupsUpdateDataManagement) pulumi.StringOutput { return v.Expect }).(pulumi.StringOutput)
}

// is force
func (o NamespaceLookupsUpdateDataManagementOutput) IsForce() pulumi.BoolOutput {
	return o.ApplyT(func(v *NamespaceLookupsUpdateDataManagement) pulumi.BoolOutput { return v.IsForce }).(pulumi.BoolOutput)
}

// The name of the lookup to operate on.
func (o NamespaceLookupsUpdateDataManagementOutput) LookupName() pulumi.StringOutput {
	return o.ApplyT(func(v *NamespaceLookupsUpdateDataManagement) pulumi.StringOutput { return v.LookupName }).(pulumi.StringOutput)
}

// The Logging Analytics namespace used for the request.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o NamespaceLookupsUpdateDataManagementOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *NamespaceLookupsUpdateDataManagement) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

func (o NamespaceLookupsUpdateDataManagementOutput) UpdateLookupFile() pulumi.StringOutput {
	return o.ApplyT(func(v *NamespaceLookupsUpdateDataManagement) pulumi.StringOutput { return v.UpdateLookupFile }).(pulumi.StringOutput)
}

type NamespaceLookupsUpdateDataManagementArrayOutput struct{ *pulumi.OutputState }

func (NamespaceLookupsUpdateDataManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*NamespaceLookupsUpdateDataManagement)(nil)).Elem()
}

func (o NamespaceLookupsUpdateDataManagementArrayOutput) ToNamespaceLookupsUpdateDataManagementArrayOutput() NamespaceLookupsUpdateDataManagementArrayOutput {
	return o
}

func (o NamespaceLookupsUpdateDataManagementArrayOutput) ToNamespaceLookupsUpdateDataManagementArrayOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementArrayOutput {
	return o
}

func (o NamespaceLookupsUpdateDataManagementArrayOutput) Index(i pulumi.IntInput) NamespaceLookupsUpdateDataManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *NamespaceLookupsUpdateDataManagement {
		return vs[0].([]*NamespaceLookupsUpdateDataManagement)[vs[1].(int)]
	}).(NamespaceLookupsUpdateDataManagementOutput)
}

type NamespaceLookupsUpdateDataManagementMapOutput struct{ *pulumi.OutputState }

func (NamespaceLookupsUpdateDataManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*NamespaceLookupsUpdateDataManagement)(nil)).Elem()
}

func (o NamespaceLookupsUpdateDataManagementMapOutput) ToNamespaceLookupsUpdateDataManagementMapOutput() NamespaceLookupsUpdateDataManagementMapOutput {
	return o
}

func (o NamespaceLookupsUpdateDataManagementMapOutput) ToNamespaceLookupsUpdateDataManagementMapOutputWithContext(ctx context.Context) NamespaceLookupsUpdateDataManagementMapOutput {
	return o
}

func (o NamespaceLookupsUpdateDataManagementMapOutput) MapIndex(k pulumi.StringInput) NamespaceLookupsUpdateDataManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *NamespaceLookupsUpdateDataManagement {
		return vs[0].(map[string]*NamespaceLookupsUpdateDataManagement)[vs[1].(string)]
	}).(NamespaceLookupsUpdateDataManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*NamespaceLookupsUpdateDataManagementInput)(nil)).Elem(), &NamespaceLookupsUpdateDataManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*NamespaceLookupsUpdateDataManagementArrayInput)(nil)).Elem(), NamespaceLookupsUpdateDataManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*NamespaceLookupsUpdateDataManagementMapInput)(nil)).Elem(), NamespaceLookupsUpdateDataManagementMap{})
	pulumi.RegisterOutputType(NamespaceLookupsUpdateDataManagementOutput{})
	pulumi.RegisterOutputType(NamespaceLookupsUpdateDataManagementArrayOutput{})
	pulumi.RegisterOutputType(NamespaceLookupsUpdateDataManagementMapOutput{})
}
