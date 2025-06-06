// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package blockchain

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Osns in Oracle Cloud Infrastructure Blockchain service.
//
// # List Blockchain Platform OSNs
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/blockchain"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := blockchain.GetOsns(ctx, &blockchain.GetOsnsArgs{
//				BlockchainPlatformId: testBlockchainPlatform.Id,
//				DisplayName:          pulumi.StringRef(osnDisplayName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOsns(ctx *pulumi.Context, args *GetOsnsArgs, opts ...pulumi.InvokeOption) (*GetOsnsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetOsnsResult
	err := ctx.Invoke("oci:Blockchain/getOsns:getOsns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOsns.
type GetOsnsArgs struct {
	// Unique service identifier.
	BlockchainPlatformId string `pulumi:"blockchainPlatformId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Example: `My new resource`
	DisplayName *string         `pulumi:"displayName"`
	Filters     []GetOsnsFilter `pulumi:"filters"`
}

// A collection of values returned by getOsns.
type GetOsnsResult struct {
	BlockchainPlatformId string          `pulumi:"blockchainPlatformId"`
	DisplayName          *string         `pulumi:"displayName"`
	Filters              []GetOsnsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of osn_collection.
	OsnCollections []GetOsnsOsnCollection `pulumi:"osnCollections"`
}

func GetOsnsOutput(ctx *pulumi.Context, args GetOsnsOutputArgs, opts ...pulumi.InvokeOption) GetOsnsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetOsnsResultOutput, error) {
			args := v.(GetOsnsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Blockchain/getOsns:getOsns", args, GetOsnsResultOutput{}, options).(GetOsnsResultOutput), nil
		}).(GetOsnsResultOutput)
}

// A collection of arguments for invoking getOsns.
type GetOsnsOutputArgs struct {
	// Unique service identifier.
	BlockchainPlatformId pulumi.StringInput `pulumi:"blockchainPlatformId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Example: `My new resource`
	DisplayName pulumi.StringPtrInput   `pulumi:"displayName"`
	Filters     GetOsnsFilterArrayInput `pulumi:"filters"`
}

func (GetOsnsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOsnsArgs)(nil)).Elem()
}

// A collection of values returned by getOsns.
type GetOsnsResultOutput struct{ *pulumi.OutputState }

func (GetOsnsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOsnsResult)(nil)).Elem()
}

func (o GetOsnsResultOutput) ToGetOsnsResultOutput() GetOsnsResultOutput {
	return o
}

func (o GetOsnsResultOutput) ToGetOsnsResultOutputWithContext(ctx context.Context) GetOsnsResultOutput {
	return o
}

func (o GetOsnsResultOutput) BlockchainPlatformId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOsnsResult) string { return v.BlockchainPlatformId }).(pulumi.StringOutput)
}

func (o GetOsnsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOsnsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetOsnsResultOutput) Filters() GetOsnsFilterArrayOutput {
	return o.ApplyT(func(v GetOsnsResult) []GetOsnsFilter { return v.Filters }).(GetOsnsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetOsnsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetOsnsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of osn_collection.
func (o GetOsnsResultOutput) OsnCollections() GetOsnsOsnCollectionArrayOutput {
	return o.ApplyT(func(v GetOsnsResult) []GetOsnsOsnCollection { return v.OsnCollections }).(GetOsnsOsnCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOsnsResultOutput{})
}
