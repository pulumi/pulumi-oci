// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loganalytics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Namespace Storage Recall Count resource in Oracle Cloud Infrastructure Log Analytics service.
//
// # This API gets the number of recalls made and the maximum recalls that can be made
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/LogAnalytics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := LogAnalytics.GetNamespaceStorageRecallCount(ctx, &loganalytics.GetNamespaceStorageRecallCountArgs{
//				Namespace: _var.Namespace_storage_recall_count_namespace,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNamespaceStorageRecallCount(ctx *pulumi.Context, args *GetNamespaceStorageRecallCountArgs, opts ...pulumi.InvokeOption) (*GetNamespaceStorageRecallCountResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetNamespaceStorageRecallCountResult
	err := ctx.Invoke("oci:LogAnalytics/getNamespaceStorageRecallCount:getNamespaceStorageRecallCount", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNamespaceStorageRecallCount.
type GetNamespaceStorageRecallCountArgs struct {
	// The Logging Analytics namespace used for the request.
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by getNamespaceStorageRecallCount.
type GetNamespaceStorageRecallCountResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id        string `pulumi:"id"`
	Namespace string `pulumi:"namespace"`
	// This is the total number of recalls made so far
	RecallCount int `pulumi:"recallCount"`
	// This is the number of recalls that failed
	RecallFailed int `pulumi:"recallFailed"`
	// This is the maximum number of recalls (including successful and pending recalls) allowed
	RecallLimit int `pulumi:"recallLimit"`
	// This is the number of recalls in pending state
	RecallPending int `pulumi:"recallPending"`
	// This is the number of recalls that succeeded
	RecallSucceeded int `pulumi:"recallSucceeded"`
}

func GetNamespaceStorageRecallCountOutput(ctx *pulumi.Context, args GetNamespaceStorageRecallCountOutputArgs, opts ...pulumi.InvokeOption) GetNamespaceStorageRecallCountResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetNamespaceStorageRecallCountResult, error) {
			args := v.(GetNamespaceStorageRecallCountArgs)
			r, err := GetNamespaceStorageRecallCount(ctx, &args, opts...)
			var s GetNamespaceStorageRecallCountResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetNamespaceStorageRecallCountResultOutput)
}

// A collection of arguments for invoking getNamespaceStorageRecallCount.
type GetNamespaceStorageRecallCountOutputArgs struct {
	// The Logging Analytics namespace used for the request.
	Namespace pulumi.StringInput `pulumi:"namespace"`
}

func (GetNamespaceStorageRecallCountOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNamespaceStorageRecallCountArgs)(nil)).Elem()
}

// A collection of values returned by getNamespaceStorageRecallCount.
type GetNamespaceStorageRecallCountResultOutput struct{ *pulumi.OutputState }

func (GetNamespaceStorageRecallCountResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNamespaceStorageRecallCountResult)(nil)).Elem()
}

func (o GetNamespaceStorageRecallCountResultOutput) ToGetNamespaceStorageRecallCountResultOutput() GetNamespaceStorageRecallCountResultOutput {
	return o
}

func (o GetNamespaceStorageRecallCountResultOutput) ToGetNamespaceStorageRecallCountResultOutputWithContext(ctx context.Context) GetNamespaceStorageRecallCountResultOutput {
	return o
}

func (o GetNamespaceStorageRecallCountResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetNamespaceStorageRecallCountResult] {
	return pulumix.Output[GetNamespaceStorageRecallCountResult]{
		OutputState: o.OutputState,
	}
}

// The provider-assigned unique ID for this managed resource.
func (o GetNamespaceStorageRecallCountResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetNamespaceStorageRecallCountResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// This is the total number of recalls made so far
func (o GetNamespaceStorageRecallCountResultOutput) RecallCount() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) int { return v.RecallCount }).(pulumi.IntOutput)
}

// This is the number of recalls that failed
func (o GetNamespaceStorageRecallCountResultOutput) RecallFailed() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) int { return v.RecallFailed }).(pulumi.IntOutput)
}

// This is the maximum number of recalls (including successful and pending recalls) allowed
func (o GetNamespaceStorageRecallCountResultOutput) RecallLimit() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) int { return v.RecallLimit }).(pulumi.IntOutput)
}

// This is the number of recalls in pending state
func (o GetNamespaceStorageRecallCountResultOutput) RecallPending() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) int { return v.RecallPending }).(pulumi.IntOutput)
}

// This is the number of recalls that succeeded
func (o GetNamespaceStorageRecallCountResultOutput) RecallSucceeded() pulumi.IntOutput {
	return o.ApplyT(func(v GetNamespaceStorageRecallCountResult) int { return v.RecallSucceeded }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNamespaceStorageRecallCountResultOutput{})
}