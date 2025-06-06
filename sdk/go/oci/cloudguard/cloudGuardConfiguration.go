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

// This resource provides the Cloud Guard Configuration resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Updates configuration details for a Cloud Guard tenancy, identified by root compartment OCID.
// The reporting region cannot be updated once created.
type CloudGuardConfiguration struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment in which to list resources.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The reporting region
	ReportingRegion pulumi.StringOutput `pulumi:"reportingRegion"`
	// (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
	SelfManageResources pulumi.BoolOutput `pulumi:"selfManageResources"`
	// (Updatable) Status of Cloud Guard tenant
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status pulumi.StringOutput `pulumi:"status"`
}

// NewCloudGuardConfiguration registers a new resource with the given unique name, arguments, and options.
func NewCloudGuardConfiguration(ctx *pulumi.Context,
	name string, args *CloudGuardConfigurationArgs, opts ...pulumi.ResourceOption) (*CloudGuardConfiguration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ReportingRegion == nil {
		return nil, errors.New("invalid value for required argument 'ReportingRegion'")
	}
	if args.Status == nil {
		return nil, errors.New("invalid value for required argument 'Status'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource CloudGuardConfiguration
	err := ctx.RegisterResource("oci:CloudGuard/cloudGuardConfiguration:CloudGuardConfiguration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCloudGuardConfiguration gets an existing CloudGuardConfiguration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCloudGuardConfiguration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CloudGuardConfigurationState, opts ...pulumi.ResourceOption) (*CloudGuardConfiguration, error) {
	var resource CloudGuardConfiguration
	err := ctx.ReadResource("oci:CloudGuard/cloudGuardConfiguration:CloudGuardConfiguration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CloudGuardConfiguration resources.
type cloudGuardConfigurationState struct {
	// (Updatable) The OCID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The reporting region
	ReportingRegion *string `pulumi:"reportingRegion"`
	// (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
	SelfManageResources *bool `pulumi:"selfManageResources"`
	// (Updatable) Status of Cloud Guard tenant
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status *string `pulumi:"status"`
}

type CloudGuardConfigurationState struct {
	// (Updatable) The OCID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The reporting region
	ReportingRegion pulumi.StringPtrInput
	// (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
	SelfManageResources pulumi.BoolPtrInput
	// (Updatable) Status of Cloud Guard tenant
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status pulumi.StringPtrInput
}

func (CloudGuardConfigurationState) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardConfigurationState)(nil)).Elem()
}

type cloudGuardConfigurationArgs struct {
	// (Updatable) The OCID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The reporting region
	ReportingRegion string `pulumi:"reportingRegion"`
	// (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
	SelfManageResources *bool `pulumi:"selfManageResources"`
	// (Updatable) Status of Cloud Guard tenant
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status string `pulumi:"status"`
}

// The set of arguments for constructing a CloudGuardConfiguration resource.
type CloudGuardConfigurationArgs struct {
	// (Updatable) The OCID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput
	// (Updatable) The reporting region
	ReportingRegion pulumi.StringInput
	// (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
	SelfManageResources pulumi.BoolPtrInput
	// (Updatable) Status of Cloud Guard tenant
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status pulumi.StringInput
}

func (CloudGuardConfigurationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardConfigurationArgs)(nil)).Elem()
}

type CloudGuardConfigurationInput interface {
	pulumi.Input

	ToCloudGuardConfigurationOutput() CloudGuardConfigurationOutput
	ToCloudGuardConfigurationOutputWithContext(ctx context.Context) CloudGuardConfigurationOutput
}

func (*CloudGuardConfiguration) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardConfiguration)(nil)).Elem()
}

func (i *CloudGuardConfiguration) ToCloudGuardConfigurationOutput() CloudGuardConfigurationOutput {
	return i.ToCloudGuardConfigurationOutputWithContext(context.Background())
}

func (i *CloudGuardConfiguration) ToCloudGuardConfigurationOutputWithContext(ctx context.Context) CloudGuardConfigurationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardConfigurationOutput)
}

// CloudGuardConfigurationArrayInput is an input type that accepts CloudGuardConfigurationArray and CloudGuardConfigurationArrayOutput values.
// You can construct a concrete instance of `CloudGuardConfigurationArrayInput` via:
//
//	CloudGuardConfigurationArray{ CloudGuardConfigurationArgs{...} }
type CloudGuardConfigurationArrayInput interface {
	pulumi.Input

	ToCloudGuardConfigurationArrayOutput() CloudGuardConfigurationArrayOutput
	ToCloudGuardConfigurationArrayOutputWithContext(context.Context) CloudGuardConfigurationArrayOutput
}

type CloudGuardConfigurationArray []CloudGuardConfigurationInput

func (CloudGuardConfigurationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CloudGuardConfiguration)(nil)).Elem()
}

func (i CloudGuardConfigurationArray) ToCloudGuardConfigurationArrayOutput() CloudGuardConfigurationArrayOutput {
	return i.ToCloudGuardConfigurationArrayOutputWithContext(context.Background())
}

func (i CloudGuardConfigurationArray) ToCloudGuardConfigurationArrayOutputWithContext(ctx context.Context) CloudGuardConfigurationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardConfigurationArrayOutput)
}

// CloudGuardConfigurationMapInput is an input type that accepts CloudGuardConfigurationMap and CloudGuardConfigurationMapOutput values.
// You can construct a concrete instance of `CloudGuardConfigurationMapInput` via:
//
//	CloudGuardConfigurationMap{ "key": CloudGuardConfigurationArgs{...} }
type CloudGuardConfigurationMapInput interface {
	pulumi.Input

	ToCloudGuardConfigurationMapOutput() CloudGuardConfigurationMapOutput
	ToCloudGuardConfigurationMapOutputWithContext(context.Context) CloudGuardConfigurationMapOutput
}

type CloudGuardConfigurationMap map[string]CloudGuardConfigurationInput

func (CloudGuardConfigurationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CloudGuardConfiguration)(nil)).Elem()
}

func (i CloudGuardConfigurationMap) ToCloudGuardConfigurationMapOutput() CloudGuardConfigurationMapOutput {
	return i.ToCloudGuardConfigurationMapOutputWithContext(context.Background())
}

func (i CloudGuardConfigurationMap) ToCloudGuardConfigurationMapOutputWithContext(ctx context.Context) CloudGuardConfigurationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardConfigurationMapOutput)
}

type CloudGuardConfigurationOutput struct{ *pulumi.OutputState }

func (CloudGuardConfigurationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardConfiguration)(nil)).Elem()
}

func (o CloudGuardConfigurationOutput) ToCloudGuardConfigurationOutput() CloudGuardConfigurationOutput {
	return o
}

func (o CloudGuardConfigurationOutput) ToCloudGuardConfigurationOutputWithContext(ctx context.Context) CloudGuardConfigurationOutput {
	return o
}

// (Updatable) The OCID of the compartment in which to list resources.
func (o CloudGuardConfigurationOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardConfiguration) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The reporting region
func (o CloudGuardConfigurationOutput) ReportingRegion() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardConfiguration) pulumi.StringOutput { return v.ReportingRegion }).(pulumi.StringOutput)
}

// (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
func (o CloudGuardConfigurationOutput) SelfManageResources() pulumi.BoolOutput {
	return o.ApplyT(func(v *CloudGuardConfiguration) pulumi.BoolOutput { return v.SelfManageResources }).(pulumi.BoolOutput)
}

// (Updatable) Status of Cloud Guard tenant
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o CloudGuardConfigurationOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardConfiguration) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

type CloudGuardConfigurationArrayOutput struct{ *pulumi.OutputState }

func (CloudGuardConfigurationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CloudGuardConfiguration)(nil)).Elem()
}

func (o CloudGuardConfigurationArrayOutput) ToCloudGuardConfigurationArrayOutput() CloudGuardConfigurationArrayOutput {
	return o
}

func (o CloudGuardConfigurationArrayOutput) ToCloudGuardConfigurationArrayOutputWithContext(ctx context.Context) CloudGuardConfigurationArrayOutput {
	return o
}

func (o CloudGuardConfigurationArrayOutput) Index(i pulumi.IntInput) CloudGuardConfigurationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *CloudGuardConfiguration {
		return vs[0].([]*CloudGuardConfiguration)[vs[1].(int)]
	}).(CloudGuardConfigurationOutput)
}

type CloudGuardConfigurationMapOutput struct{ *pulumi.OutputState }

func (CloudGuardConfigurationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CloudGuardConfiguration)(nil)).Elem()
}

func (o CloudGuardConfigurationMapOutput) ToCloudGuardConfigurationMapOutput() CloudGuardConfigurationMapOutput {
	return o
}

func (o CloudGuardConfigurationMapOutput) ToCloudGuardConfigurationMapOutputWithContext(ctx context.Context) CloudGuardConfigurationMapOutput {
	return o
}

func (o CloudGuardConfigurationMapOutput) MapIndex(k pulumi.StringInput) CloudGuardConfigurationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *CloudGuardConfiguration {
		return vs[0].(map[string]*CloudGuardConfiguration)[vs[1].(string)]
	}).(CloudGuardConfigurationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*CloudGuardConfigurationInput)(nil)).Elem(), &CloudGuardConfiguration{})
	pulumi.RegisterInputType(reflect.TypeOf((*CloudGuardConfigurationArrayInput)(nil)).Elem(), CloudGuardConfigurationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*CloudGuardConfigurationMapInput)(nil)).Elem(), CloudGuardConfigurationMap{})
	pulumi.RegisterOutputType(CloudGuardConfigurationOutput{})
	pulumi.RegisterOutputType(CloudGuardConfigurationArrayOutput{})
	pulumi.RegisterOutputType(CloudGuardConfigurationMapOutput{})
}
