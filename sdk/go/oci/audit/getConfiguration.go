// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package audit

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Audit service.
//
// # Get the configuration
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/audit"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := audit.GetConfiguration(ctx, &audit.GetConfigurationArgs{
//				CompartmentId: tenancyOcid,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupConfiguration(ctx *pulumi.Context, args *LookupConfigurationArgs, opts ...pulumi.InvokeOption) (*LookupConfigurationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupConfigurationResult
	err := ctx.Invoke("oci:Audit/getConfiguration:getConfiguration", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConfiguration.
type LookupConfigurationArgs struct {
	// ID of the root compartment (tenancy)
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by getConfiguration.
type LookupConfigurationResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	Id            string `pulumi:"id"`
	// The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
	RetentionPeriodDays int `pulumi:"retentionPeriodDays"`
}

func LookupConfigurationOutput(ctx *pulumi.Context, args LookupConfigurationOutputArgs, opts ...pulumi.InvokeOption) LookupConfigurationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupConfigurationResultOutput, error) {
			args := v.(LookupConfigurationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Audit/getConfiguration:getConfiguration", args, LookupConfigurationResultOutput{}, options).(LookupConfigurationResultOutput), nil
		}).(LookupConfigurationResultOutput)
}

// A collection of arguments for invoking getConfiguration.
type LookupConfigurationOutputArgs struct {
	// ID of the root compartment (tenancy)
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
}

func (LookupConfigurationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConfigurationArgs)(nil)).Elem()
}

// A collection of values returned by getConfiguration.
type LookupConfigurationResultOutput struct{ *pulumi.OutputState }

func (LookupConfigurationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConfigurationResult)(nil)).Elem()
}

func (o LookupConfigurationResultOutput) ToLookupConfigurationResultOutput() LookupConfigurationResultOutput {
	return o
}

func (o LookupConfigurationResultOutput) ToLookupConfigurationResultOutputWithContext(ctx context.Context) LookupConfigurationResultOutput {
	return o
}

func (o LookupConfigurationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigurationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o LookupConfigurationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConfigurationResult) string { return v.Id }).(pulumi.StringOutput)
}

// The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
func (o LookupConfigurationResultOutput) RetentionPeriodDays() pulumi.IntOutput {
	return o.ApplyT(func(v LookupConfigurationResult) int { return v.RetentionPeriodDays }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupConfigurationResultOutput{})
}
