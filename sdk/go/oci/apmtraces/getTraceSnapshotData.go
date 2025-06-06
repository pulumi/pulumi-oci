// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apmtraces

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Trace Snapshot Data resource in Oracle Cloud Infrastructure Apm Traces service.
//
// Gets the trace snapshots data identified by trace ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/apmtraces"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := apmtraces.GetTraceSnapshotData(ctx, &apmtraces.GetTraceSnapshotDataArgs{
//				ApmDomainId:  testApmDomain.Id,
//				TraceKey:     traceSnapshotDataTraceKey,
//				IsSummarized: pulumi.BoolRef(traceSnapshotDataIsSummarized),
//				SnapshotTime: pulumi.StringRef(traceSnapshotDataSnapshotTime),
//				ThreadId:     pulumi.StringRef(testThread.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetTraceSnapshotData(ctx *pulumi.Context, args *GetTraceSnapshotDataArgs, opts ...pulumi.InvokeOption) (*GetTraceSnapshotDataResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetTraceSnapshotDataResult
	err := ctx.Invoke("oci:ApmTraces/getTraceSnapshotData:getTraceSnapshotData", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTraceSnapshotData.
type GetTraceSnapshotDataArgs struct {
	// The APM Domain ID for the intended request.
	ApmDomainId string `pulumi:"apmDomainId"`
	// If enabled, only span level details are sent.
	IsSummarized *bool `pulumi:"isSummarized"`
	// Epoch time of snapshot.
	SnapshotTime *string `pulumi:"snapshotTime"`
	// Thread ID for which snapshots need to be retrieved. This identifier of a thread is a long positive number generated when a thread is created.
	ThreadId *string `pulumi:"threadId"`
	// Unique Application Performance Monitoring trace identifier (traceId).
	TraceKey string `pulumi:"traceKey"`
}

// A collection of values returned by getTraceSnapshotData.
type GetTraceSnapshotDataResult struct {
	ApmDomainId string `pulumi:"apmDomainId"`
	// The provider-assigned unique ID for this managed resource.
	Id           string `pulumi:"id"`
	IsSummarized *bool  `pulumi:"isSummarized"`
	// Name of the property.
	Key          string  `pulumi:"key"`
	SnapshotTime *string `pulumi:"snapshotTime"`
	ThreadId     *string `pulumi:"threadId"`
	// End time of the trace.
	TimeEnded string `pulumi:"timeEnded"`
	// Start time of the trace.
	TimeStarted string `pulumi:"timeStarted"`
	TraceKey    string `pulumi:"traceKey"`
	// Trace snapshots properties.
	TraceSnapshotDetails []GetTraceSnapshotDataTraceSnapshotDetail `pulumi:"traceSnapshotDetails"`
}

func GetTraceSnapshotDataOutput(ctx *pulumi.Context, args GetTraceSnapshotDataOutputArgs, opts ...pulumi.InvokeOption) GetTraceSnapshotDataResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetTraceSnapshotDataResultOutput, error) {
			args := v.(GetTraceSnapshotDataArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApmTraces/getTraceSnapshotData:getTraceSnapshotData", args, GetTraceSnapshotDataResultOutput{}, options).(GetTraceSnapshotDataResultOutput), nil
		}).(GetTraceSnapshotDataResultOutput)
}

// A collection of arguments for invoking getTraceSnapshotData.
type GetTraceSnapshotDataOutputArgs struct {
	// The APM Domain ID for the intended request.
	ApmDomainId pulumi.StringInput `pulumi:"apmDomainId"`
	// If enabled, only span level details are sent.
	IsSummarized pulumi.BoolPtrInput `pulumi:"isSummarized"`
	// Epoch time of snapshot.
	SnapshotTime pulumi.StringPtrInput `pulumi:"snapshotTime"`
	// Thread ID for which snapshots need to be retrieved. This identifier of a thread is a long positive number generated when a thread is created.
	ThreadId pulumi.StringPtrInput `pulumi:"threadId"`
	// Unique Application Performance Monitoring trace identifier (traceId).
	TraceKey pulumi.StringInput `pulumi:"traceKey"`
}

func (GetTraceSnapshotDataOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTraceSnapshotDataArgs)(nil)).Elem()
}

// A collection of values returned by getTraceSnapshotData.
type GetTraceSnapshotDataResultOutput struct{ *pulumi.OutputState }

func (GetTraceSnapshotDataResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTraceSnapshotDataResult)(nil)).Elem()
}

func (o GetTraceSnapshotDataResultOutput) ToGetTraceSnapshotDataResultOutput() GetTraceSnapshotDataResultOutput {
	return o
}

func (o GetTraceSnapshotDataResultOutput) ToGetTraceSnapshotDataResultOutputWithContext(ctx context.Context) GetTraceSnapshotDataResultOutput {
	return o
}

func (o GetTraceSnapshotDataResultOutput) ApmDomainId() pulumi.StringOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) string { return v.ApmDomainId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetTraceSnapshotDataResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetTraceSnapshotDataResultOutput) IsSummarized() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) *bool { return v.IsSummarized }).(pulumi.BoolPtrOutput)
}

// Name of the property.
func (o GetTraceSnapshotDataResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) string { return v.Key }).(pulumi.StringOutput)
}

func (o GetTraceSnapshotDataResultOutput) SnapshotTime() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) *string { return v.SnapshotTime }).(pulumi.StringPtrOutput)
}

func (o GetTraceSnapshotDataResultOutput) ThreadId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) *string { return v.ThreadId }).(pulumi.StringPtrOutput)
}

// End time of the trace.
func (o GetTraceSnapshotDataResultOutput) TimeEnded() pulumi.StringOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) string { return v.TimeEnded }).(pulumi.StringOutput)
}

// Start time of the trace.
func (o GetTraceSnapshotDataResultOutput) TimeStarted() pulumi.StringOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) string { return v.TimeStarted }).(pulumi.StringOutput)
}

func (o GetTraceSnapshotDataResultOutput) TraceKey() pulumi.StringOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) string { return v.TraceKey }).(pulumi.StringOutput)
}

// Trace snapshots properties.
func (o GetTraceSnapshotDataResultOutput) TraceSnapshotDetails() GetTraceSnapshotDataTraceSnapshotDetailArrayOutput {
	return o.ApplyT(func(v GetTraceSnapshotDataResult) []GetTraceSnapshotDataTraceSnapshotDetail {
		return v.TraceSnapshotDetails
	}).(GetTraceSnapshotDataTraceSnapshotDetailArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetTraceSnapshotDataResultOutput{})
}
