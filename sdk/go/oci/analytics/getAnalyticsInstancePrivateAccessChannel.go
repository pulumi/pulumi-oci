// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package analytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Analytics Instance Private Access Channel resource in Oracle Cloud Infrastructure Analytics service.
//
// Retrieve private access channel in the specified Analytics Instance.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/analytics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := analytics.GetAnalyticsInstancePrivateAccessChannel(ctx, &analytics.GetAnalyticsInstancePrivateAccessChannelArgs{
//				AnalyticsInstanceId:     testAnalyticsInstance.Id,
//				PrivateAccessChannelKey: analyticsInstancePrivateAccessChannelPrivateAccessChannelKey,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAnalyticsInstancePrivateAccessChannel(ctx *pulumi.Context, args *LookupAnalyticsInstancePrivateAccessChannelArgs, opts ...pulumi.InvokeOption) (*LookupAnalyticsInstancePrivateAccessChannelResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupAnalyticsInstancePrivateAccessChannelResult
	err := ctx.Invoke("oci:Analytics/getAnalyticsInstancePrivateAccessChannel:getAnalyticsInstancePrivateAccessChannel", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAnalyticsInstancePrivateAccessChannel.
type LookupAnalyticsInstancePrivateAccessChannelArgs struct {
	// The OCID of the AnalyticsInstance.
	AnalyticsInstanceId string `pulumi:"analyticsInstanceId"`
	// The unique identifier key of the Private Access Channel.
	PrivateAccessChannelKey string `pulumi:"privateAccessChannelKey"`
}

// A collection of values returned by getAnalyticsInstancePrivateAccessChannel.
type LookupAnalyticsInstancePrivateAccessChannelResult struct {
	AnalyticsInstanceId string `pulumi:"analyticsInstanceId"`
	// Display Name of the Private Access Channel.
	DisplayName string `pulumi:"displayName"`
	// The list of IP addresses from the customer subnet connected to private access channel, used as a source Ip by Private Access Channel for network traffic from the AnalyticsInstance to Private Sources.
	EgressSourceIpAddresses []string `pulumi:"egressSourceIpAddresses"`
	Id                      string   `pulumi:"id"`
	// IP Address of the Private Access channel.
	IpAddress string `pulumi:"ipAddress"`
	// Private Access Channel unique identifier key.
	Key string `pulumi:"key"`
	// Network Security Group OCIDs for an Analytics instance.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	PrivateAccessChannelKey string   `pulumi:"privateAccessChannelKey"`
	// List of Private Source DNS zones registered with Private Access Channel, where datasource hostnames from these dns zones / domains will be resolved in the peered VCN for access from Analytics Instance. Min of 1 is required and Max of 30 Private Source DNS zones can be registered.
	PrivateSourceDnsZones []GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone `pulumi:"privateSourceDnsZones"`
	// List of Private Source DB SCAN hosts registered with Private Access Channel for access from Analytics Instance.
	PrivateSourceScanHosts []GetAnalyticsInstancePrivateAccessChannelPrivateSourceScanHost `pulumi:"privateSourceScanHosts"`
	// OCID of the customer subnet connected to private access channel.
	SubnetId string `pulumi:"subnetId"`
	// OCID of the customer VCN peered with private access channel.
	VcnId string `pulumi:"vcnId"`
}

func LookupAnalyticsInstancePrivateAccessChannelOutput(ctx *pulumi.Context, args LookupAnalyticsInstancePrivateAccessChannelOutputArgs, opts ...pulumi.InvokeOption) LookupAnalyticsInstancePrivateAccessChannelResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupAnalyticsInstancePrivateAccessChannelResultOutput, error) {
			args := v.(LookupAnalyticsInstancePrivateAccessChannelArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Analytics/getAnalyticsInstancePrivateAccessChannel:getAnalyticsInstancePrivateAccessChannel", args, LookupAnalyticsInstancePrivateAccessChannelResultOutput{}, options).(LookupAnalyticsInstancePrivateAccessChannelResultOutput), nil
		}).(LookupAnalyticsInstancePrivateAccessChannelResultOutput)
}

// A collection of arguments for invoking getAnalyticsInstancePrivateAccessChannel.
type LookupAnalyticsInstancePrivateAccessChannelOutputArgs struct {
	// The OCID of the AnalyticsInstance.
	AnalyticsInstanceId pulumi.StringInput `pulumi:"analyticsInstanceId"`
	// The unique identifier key of the Private Access Channel.
	PrivateAccessChannelKey pulumi.StringInput `pulumi:"privateAccessChannelKey"`
}

func (LookupAnalyticsInstancePrivateAccessChannelOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAnalyticsInstancePrivateAccessChannelArgs)(nil)).Elem()
}

// A collection of values returned by getAnalyticsInstancePrivateAccessChannel.
type LookupAnalyticsInstancePrivateAccessChannelResultOutput struct{ *pulumi.OutputState }

func (LookupAnalyticsInstancePrivateAccessChannelResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAnalyticsInstancePrivateAccessChannelResult)(nil)).Elem()
}

func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) ToLookupAnalyticsInstancePrivateAccessChannelResultOutput() LookupAnalyticsInstancePrivateAccessChannelResultOutput {
	return o
}

func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) ToLookupAnalyticsInstancePrivateAccessChannelResultOutputWithContext(ctx context.Context) LookupAnalyticsInstancePrivateAccessChannelResultOutput {
	return o
}

func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) AnalyticsInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.AnalyticsInstanceId }).(pulumi.StringOutput)
}

// Display Name of the Private Access Channel.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The list of IP addresses from the customer subnet connected to private access channel, used as a source Ip by Private Access Channel for network traffic from the AnalyticsInstance to Private Sources.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) EgressSourceIpAddresses() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) []string { return v.EgressSourceIpAddresses }).(pulumi.StringArrayOutput)
}

func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.Id }).(pulumi.StringOutput)
}

// IP Address of the Private Access channel.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) IpAddress() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.IpAddress }).(pulumi.StringOutput)
}

// Private Access Channel unique identifier key.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.Key }).(pulumi.StringOutput)
}

// Network Security Group OCIDs for an Analytics instance.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) NetworkSecurityGroupIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) []string { return v.NetworkSecurityGroupIds }).(pulumi.StringArrayOutput)
}

func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) PrivateAccessChannelKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.PrivateAccessChannelKey }).(pulumi.StringOutput)
}

// List of Private Source DNS zones registered with Private Access Channel, where datasource hostnames from these dns zones / domains will be resolved in the peered VCN for access from Analytics Instance. Min of 1 is required and Max of 30 Private Source DNS zones can be registered.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) PrivateSourceDnsZones() GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneArrayOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) []GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZone {
		return v.PrivateSourceDnsZones
	}).(GetAnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneArrayOutput)
}

// List of Private Source DB SCAN hosts registered with Private Access Channel for access from Analytics Instance.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) PrivateSourceScanHosts() GetAnalyticsInstancePrivateAccessChannelPrivateSourceScanHostArrayOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) []GetAnalyticsInstancePrivateAccessChannelPrivateSourceScanHost {
		return v.PrivateSourceScanHosts
	}).(GetAnalyticsInstancePrivateAccessChannelPrivateSourceScanHostArrayOutput)
}

// OCID of the customer subnet connected to private access channel.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// OCID of the customer VCN peered with private access channel.
func (o LookupAnalyticsInstancePrivateAccessChannelResultOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAnalyticsInstancePrivateAccessChannelResult) string { return v.VcnId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAnalyticsInstancePrivateAccessChannelResultOutput{})
}
