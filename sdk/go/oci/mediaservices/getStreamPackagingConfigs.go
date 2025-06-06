// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Stream Packaging Configs in Oracle Cloud Infrastructure Media Services service.
//
// Lists the Stream Packaging Configurations.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/mediaservices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := mediaservices.GetStreamPackagingConfigs(ctx, &mediaservices.GetStreamPackagingConfigsArgs{
//				DistributionChannelId:   testChannel.Id,
//				DisplayName:             pulumi.StringRef(streamPackagingConfigDisplayName),
//				State:                   pulumi.StringRef(streamPackagingConfigState),
//				StreamPackagingConfigId: pulumi.StringRef(testStreamPackagingConfig.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetStreamPackagingConfigs(ctx *pulumi.Context, args *GetStreamPackagingConfigsArgs, opts ...pulumi.InvokeOption) (*GetStreamPackagingConfigsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetStreamPackagingConfigsResult
	err := ctx.Invoke("oci:MediaServices/getStreamPackagingConfigs:getStreamPackagingConfigs", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getStreamPackagingConfigs.
type GetStreamPackagingConfigsArgs struct {
	// A filter to return only the resources that match the entire display name given.
	DisplayName *string `pulumi:"displayName"`
	// Unique Stream Distribution Channel identifier.
	DistributionChannelId string                            `pulumi:"distributionChannelId"`
	Filters               []GetStreamPackagingConfigsFilter `pulumi:"filters"`
	// A filter to return only the resources with lifecycleState matching the given lifecycleState.
	State *string `pulumi:"state"`
	// Unique Stream Packaging Configuration identifier.
	StreamPackagingConfigId *string `pulumi:"streamPackagingConfigId"`
}

// A collection of values returned by getStreamPackagingConfigs.
type GetStreamPackagingConfigsResult struct {
	// The name of the stream packaging configuration. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
	DistributionChannelId string                            `pulumi:"distributionChannelId"`
	Filters               []GetStreamPackagingConfigsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the Packaging Configuration.
	State *string `pulumi:"state"`
	// The list of stream_packaging_config_collection.
	StreamPackagingConfigCollections []GetStreamPackagingConfigsStreamPackagingConfigCollection `pulumi:"streamPackagingConfigCollections"`
	StreamPackagingConfigId          *string                                                    `pulumi:"streamPackagingConfigId"`
}

func GetStreamPackagingConfigsOutput(ctx *pulumi.Context, args GetStreamPackagingConfigsOutputArgs, opts ...pulumi.InvokeOption) GetStreamPackagingConfigsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetStreamPackagingConfigsResultOutput, error) {
			args := v.(GetStreamPackagingConfigsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:MediaServices/getStreamPackagingConfigs:getStreamPackagingConfigs", args, GetStreamPackagingConfigsResultOutput{}, options).(GetStreamPackagingConfigsResultOutput), nil
		}).(GetStreamPackagingConfigsResultOutput)
}

// A collection of arguments for invoking getStreamPackagingConfigs.
type GetStreamPackagingConfigsOutputArgs struct {
	// A filter to return only the resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// Unique Stream Distribution Channel identifier.
	DistributionChannelId pulumi.StringInput                        `pulumi:"distributionChannelId"`
	Filters               GetStreamPackagingConfigsFilterArrayInput `pulumi:"filters"`
	// A filter to return only the resources with lifecycleState matching the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
	// Unique Stream Packaging Configuration identifier.
	StreamPackagingConfigId pulumi.StringPtrInput `pulumi:"streamPackagingConfigId"`
}

func (GetStreamPackagingConfigsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetStreamPackagingConfigsArgs)(nil)).Elem()
}

// A collection of values returned by getStreamPackagingConfigs.
type GetStreamPackagingConfigsResultOutput struct{ *pulumi.OutputState }

func (GetStreamPackagingConfigsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetStreamPackagingConfigsResult)(nil)).Elem()
}

func (o GetStreamPackagingConfigsResultOutput) ToGetStreamPackagingConfigsResultOutput() GetStreamPackagingConfigsResultOutput {
	return o
}

func (o GetStreamPackagingConfigsResultOutput) ToGetStreamPackagingConfigsResultOutputWithContext(ctx context.Context) GetStreamPackagingConfigsResultOutput {
	return o
}

// The name of the stream packaging configuration. Avoid entering confidential information.
func (o GetStreamPackagingConfigsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
func (o GetStreamPackagingConfigsResultOutput) DistributionChannelId() pulumi.StringOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) string { return v.DistributionChannelId }).(pulumi.StringOutput)
}

func (o GetStreamPackagingConfigsResultOutput) Filters() GetStreamPackagingConfigsFilterArrayOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) []GetStreamPackagingConfigsFilter { return v.Filters }).(GetStreamPackagingConfigsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetStreamPackagingConfigsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the Packaging Configuration.
func (o GetStreamPackagingConfigsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of stream_packaging_config_collection.
func (o GetStreamPackagingConfigsResultOutput) StreamPackagingConfigCollections() GetStreamPackagingConfigsStreamPackagingConfigCollectionArrayOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) []GetStreamPackagingConfigsStreamPackagingConfigCollection {
		return v.StreamPackagingConfigCollections
	}).(GetStreamPackagingConfigsStreamPackagingConfigCollectionArrayOutput)
}

func (o GetStreamPackagingConfigsResultOutput) StreamPackagingConfigId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetStreamPackagingConfigsResult) *string { return v.StreamPackagingConfigId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetStreamPackagingConfigsResultOutput{})
}
