// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Stream Distribution Channel resource in Oracle Cloud Infrastructure Media Services service.
//
// Gets a Stream Distribution Channel by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/MediaServices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := MediaServices.GetStreamDistributionChannel(ctx, &mediaservices.GetStreamDistributionChannelArgs{
//				StreamDistributionChannelId: oci_media_services_stream_distribution_channel.Test_stream_distribution_channel.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupStreamDistributionChannel(ctx *pulumi.Context, args *LookupStreamDistributionChannelArgs, opts ...pulumi.InvokeOption) (*LookupStreamDistributionChannelResult, error) {
	var rv LookupStreamDistributionChannelResult
	err := ctx.Invoke("oci:MediaServices/getStreamDistributionChannel:getStreamDistributionChannel", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getStreamDistributionChannel.
type LookupStreamDistributionChannelArgs struct {
	// Unique Stream Distribution Channel path identifier.
	StreamDistributionChannelId string `pulumi:"streamDistributionChannelId"`
}

// A collection of values returned by getStreamDistributionChannel.
type LookupStreamDistributionChannelResult struct {
	// Compartment Identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Stream Distribution Channel display name. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Unique domain name of the Distribution Channel.
	DomainName string `pulumi:"domainName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation.
	Id string `pulumi:"id"`
	// The current state of the Stream Distribution Channel.
	State                       string `pulumi:"state"`
	StreamDistributionChannelId string `pulumi:"streamDistributionChannelId"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time when the Stream Distribution Channel was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when the Stream Distribution Channel was updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupStreamDistributionChannelOutput(ctx *pulumi.Context, args LookupStreamDistributionChannelOutputArgs, opts ...pulumi.InvokeOption) LookupStreamDistributionChannelResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupStreamDistributionChannelResult, error) {
			args := v.(LookupStreamDistributionChannelArgs)
			r, err := LookupStreamDistributionChannel(ctx, &args, opts...)
			var s LookupStreamDistributionChannelResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupStreamDistributionChannelResultOutput)
}

// A collection of arguments for invoking getStreamDistributionChannel.
type LookupStreamDistributionChannelOutputArgs struct {
	// Unique Stream Distribution Channel path identifier.
	StreamDistributionChannelId pulumi.StringInput `pulumi:"streamDistributionChannelId"`
}

func (LookupStreamDistributionChannelOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupStreamDistributionChannelArgs)(nil)).Elem()
}

// A collection of values returned by getStreamDistributionChannel.
type LookupStreamDistributionChannelResultOutput struct{ *pulumi.OutputState }

func (LookupStreamDistributionChannelResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupStreamDistributionChannelResult)(nil)).Elem()
}

func (o LookupStreamDistributionChannelResultOutput) ToLookupStreamDistributionChannelResultOutput() LookupStreamDistributionChannelResultOutput {
	return o
}

func (o LookupStreamDistributionChannelResultOutput) ToLookupStreamDistributionChannelResultOutputWithContext(ctx context.Context) LookupStreamDistributionChannelResultOutput {
	return o
}

// Compartment Identifier.
func (o LookupStreamDistributionChannelResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupStreamDistributionChannelResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Stream Distribution Channel display name. Avoid entering confidential information.
func (o LookupStreamDistributionChannelResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Unique domain name of the Distribution Channel.
func (o LookupStreamDistributionChannelResultOutput) DomainName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.DomainName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupStreamDistributionChannelResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique identifier that is immutable on creation.
func (o LookupStreamDistributionChannelResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the Stream Distribution Channel.
func (o LookupStreamDistributionChannelResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.State }).(pulumi.StringOutput)
}

func (o LookupStreamDistributionChannelResultOutput) StreamDistributionChannelId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.StreamDistributionChannelId }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupStreamDistributionChannelResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time when the Stream Distribution Channel was created. An RFC3339 formatted datetime string.
func (o LookupStreamDistributionChannelResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the Stream Distribution Channel was updated. An RFC3339 formatted datetime string.
func (o LookupStreamDistributionChannelResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupStreamDistributionChannelResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupStreamDistributionChannelResultOutput{})
}