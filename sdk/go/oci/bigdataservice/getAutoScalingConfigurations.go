// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package bigdataservice

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func GetAutoScalingConfigurations(ctx *pulumi.Context, args *GetAutoScalingConfigurationsArgs, opts ...pulumi.InvokeOption) (*GetAutoScalingConfigurationsResult, error) {
	var rv GetAutoScalingConfigurationsResult
	err := ctx.Invoke("oci:BigDataService/getAutoScalingConfigurations:getAutoScalingConfigurations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutoScalingConfigurations.
type GetAutoScalingConfigurationsArgs struct {
	BdsInstanceId string                               `pulumi:"bdsInstanceId"`
	CompartmentId string                               `pulumi:"compartmentId"`
	DisplayName   *string                              `pulumi:"displayName"`
	Filters       []GetAutoScalingConfigurationsFilter `pulumi:"filters"`
	State         *string                              `pulumi:"state"`
}

// A collection of values returned by getAutoScalingConfigurations.
type GetAutoScalingConfigurationsResult struct {
	AutoScalingConfigurations []GetAutoScalingConfigurationsAutoScalingConfiguration `pulumi:"autoScalingConfigurations"`
	BdsInstanceId             string                                                 `pulumi:"bdsInstanceId"`
	CompartmentId             string                                                 `pulumi:"compartmentId"`
	DisplayName               *string                                                `pulumi:"displayName"`
	Filters                   []GetAutoScalingConfigurationsFilter                   `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id    string  `pulumi:"id"`
	State *string `pulumi:"state"`
}

func GetAutoScalingConfigurationsOutput(ctx *pulumi.Context, args GetAutoScalingConfigurationsOutputArgs, opts ...pulumi.InvokeOption) GetAutoScalingConfigurationsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAutoScalingConfigurationsResult, error) {
			args := v.(GetAutoScalingConfigurationsArgs)
			r, err := GetAutoScalingConfigurations(ctx, &args, opts...)
			var s GetAutoScalingConfigurationsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAutoScalingConfigurationsResultOutput)
}

// A collection of arguments for invoking getAutoScalingConfigurations.
type GetAutoScalingConfigurationsOutputArgs struct {
	BdsInstanceId pulumi.StringInput                           `pulumi:"bdsInstanceId"`
	CompartmentId pulumi.StringInput                           `pulumi:"compartmentId"`
	DisplayName   pulumi.StringPtrInput                        `pulumi:"displayName"`
	Filters       GetAutoScalingConfigurationsFilterArrayInput `pulumi:"filters"`
	State         pulumi.StringPtrInput                        `pulumi:"state"`
}

func (GetAutoScalingConfigurationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutoScalingConfigurationsArgs)(nil)).Elem()
}

// A collection of values returned by getAutoScalingConfigurations.
type GetAutoScalingConfigurationsResultOutput struct{ *pulumi.OutputState }

func (GetAutoScalingConfigurationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutoScalingConfigurationsResult)(nil)).Elem()
}

func (o GetAutoScalingConfigurationsResultOutput) ToGetAutoScalingConfigurationsResultOutput() GetAutoScalingConfigurationsResultOutput {
	return o
}

func (o GetAutoScalingConfigurationsResultOutput) ToGetAutoScalingConfigurationsResultOutputWithContext(ctx context.Context) GetAutoScalingConfigurationsResultOutput {
	return o
}

func (o GetAutoScalingConfigurationsResultOutput) AutoScalingConfigurations() GetAutoScalingConfigurationsAutoScalingConfigurationArrayOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) []GetAutoScalingConfigurationsAutoScalingConfiguration {
		return v.AutoScalingConfigurations
	}).(GetAutoScalingConfigurationsAutoScalingConfigurationArrayOutput)
}

func (o GetAutoScalingConfigurationsResultOutput) BdsInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) string { return v.BdsInstanceId }).(pulumi.StringOutput)
}

func (o GetAutoScalingConfigurationsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetAutoScalingConfigurationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAutoScalingConfigurationsResultOutput) Filters() GetAutoScalingConfigurationsFilterArrayOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) []GetAutoScalingConfigurationsFilter { return v.Filters }).(GetAutoScalingConfigurationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAutoScalingConfigurationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetAutoScalingConfigurationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutoScalingConfigurationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAutoScalingConfigurationsResultOutput{})
}