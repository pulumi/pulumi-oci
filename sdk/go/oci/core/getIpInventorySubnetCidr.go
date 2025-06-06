// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Ip Inventory Subnet Cidr resource in Oracle Cloud Infrastructure Core service.
//
// Gets the CIDR utilization data of the specified subnet. Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
//			_, err := core.GetIpInventorySubnetCidr(ctx, &core.GetIpInventorySubnetCidrArgs{
//				SubnetId: testSubnet.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetIpInventorySubnetCidr(ctx *pulumi.Context, args *GetIpInventorySubnetCidrArgs, opts ...pulumi.InvokeOption) (*GetIpInventorySubnetCidrResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetIpInventorySubnetCidrResult
	err := ctx.Invoke("oci:Core/getIpInventorySubnetCidr:getIpInventorySubnetCidr", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getIpInventorySubnetCidr.
type GetIpInventorySubnetCidrArgs struct {
	// Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId string `pulumi:"subnetId"`
}

// A collection of values returned by getIpInventorySubnetCidr.
type GetIpInventorySubnetCidrResult struct {
	// Compartment of the subnet.
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Lists 'IpInventoryCidrUtilizationSummary` object.
	IpInventoryCidrUtilizationSummaries []GetIpInventorySubnetCidrIpInventoryCidrUtilizationSummary `pulumi:"ipInventoryCidrUtilizationSummaries"`
	// Specifies the count for the number of results for the response.
	IpInventorySubnetCidrCount int `pulumi:"ipInventorySubnetCidrCount"`
	// The Timestamp of the latest update from the database in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	LastUpdatedTimestamp string `pulumi:"lastUpdatedTimestamp"`
	// Indicates the status of the data.
	Message  string `pulumi:"message"`
	SubnetId string `pulumi:"subnetId"`
}

func GetIpInventorySubnetCidrOutput(ctx *pulumi.Context, args GetIpInventorySubnetCidrOutputArgs, opts ...pulumi.InvokeOption) GetIpInventorySubnetCidrResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetIpInventorySubnetCidrResultOutput, error) {
			args := v.(GetIpInventorySubnetCidrArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getIpInventorySubnetCidr:getIpInventorySubnetCidr", args, GetIpInventorySubnetCidrResultOutput{}, options).(GetIpInventorySubnetCidrResultOutput), nil
		}).(GetIpInventorySubnetCidrResultOutput)
}

// A collection of arguments for invoking getIpInventorySubnetCidr.
type GetIpInventorySubnetCidrOutputArgs struct {
	// Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId pulumi.StringInput `pulumi:"subnetId"`
}

func (GetIpInventorySubnetCidrOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIpInventorySubnetCidrArgs)(nil)).Elem()
}

// A collection of values returned by getIpInventorySubnetCidr.
type GetIpInventorySubnetCidrResultOutput struct{ *pulumi.OutputState }

func (GetIpInventorySubnetCidrResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIpInventorySubnetCidrResult)(nil)).Elem()
}

func (o GetIpInventorySubnetCidrResultOutput) ToGetIpInventorySubnetCidrResultOutput() GetIpInventorySubnetCidrResultOutput {
	return o
}

func (o GetIpInventorySubnetCidrResultOutput) ToGetIpInventorySubnetCidrResultOutputWithContext(ctx context.Context) GetIpInventorySubnetCidrResultOutput {
	return o
}

// Compartment of the subnet.
func (o GetIpInventorySubnetCidrResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetIpInventorySubnetCidrResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) string { return v.Id }).(pulumi.StringOutput)
}

// Lists 'IpInventoryCidrUtilizationSummary` object.
func (o GetIpInventorySubnetCidrResultOutput) IpInventoryCidrUtilizationSummaries() GetIpInventorySubnetCidrIpInventoryCidrUtilizationSummaryArrayOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) []GetIpInventorySubnetCidrIpInventoryCidrUtilizationSummary {
		return v.IpInventoryCidrUtilizationSummaries
	}).(GetIpInventorySubnetCidrIpInventoryCidrUtilizationSummaryArrayOutput)
}

// Specifies the count for the number of results for the response.
func (o GetIpInventorySubnetCidrResultOutput) IpInventorySubnetCidrCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) int { return v.IpInventorySubnetCidrCount }).(pulumi.IntOutput)
}

// The Timestamp of the latest update from the database in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
func (o GetIpInventorySubnetCidrResultOutput) LastUpdatedTimestamp() pulumi.StringOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) string { return v.LastUpdatedTimestamp }).(pulumi.StringOutput)
}

// Indicates the status of the data.
func (o GetIpInventorySubnetCidrResultOutput) Message() pulumi.StringOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) string { return v.Message }).(pulumi.StringOutput)
}

func (o GetIpInventorySubnetCidrResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v GetIpInventorySubnetCidrResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetIpInventorySubnetCidrResultOutput{})
}
