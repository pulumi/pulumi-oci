// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataflow

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Run Logs in Oracle Cloud Infrastructure Data Flow service.
//
// Retrieves summaries of the run's logs.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataFlow"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataFlow.GetRunLogs(ctx, &dataflow.GetRunLogsArgs{
//				RunId: oci_dataflow_run.Test_run.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRunLogs(ctx *pulumi.Context, args *GetRunLogsArgs, opts ...pulumi.InvokeOption) (*GetRunLogsResult, error) {
	var rv GetRunLogsResult
	err := ctx.Invoke("oci:DataFlow/getRunLogs:getRunLogs", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRunLogs.
type GetRunLogsArgs struct {
	Filters []GetRunLogsFilter `pulumi:"filters"`
	// The unique ID for the run
	RunId string `pulumi:"runId"`
}

// A collection of values returned by getRunLogs.
type GetRunLogsResult struct {
	Filters []GetRunLogsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id    string `pulumi:"id"`
	RunId string `pulumi:"runId"`
	// The list of run_logs.
	RunLogs []GetRunLogsRunLog `pulumi:"runLogs"`
}

func GetRunLogsOutput(ctx *pulumi.Context, args GetRunLogsOutputArgs, opts ...pulumi.InvokeOption) GetRunLogsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRunLogsResult, error) {
			args := v.(GetRunLogsArgs)
			r, err := GetRunLogs(ctx, &args, opts...)
			var s GetRunLogsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRunLogsResultOutput)
}

// A collection of arguments for invoking getRunLogs.
type GetRunLogsOutputArgs struct {
	Filters GetRunLogsFilterArrayInput `pulumi:"filters"`
	// The unique ID for the run
	RunId pulumi.StringInput `pulumi:"runId"`
}

func (GetRunLogsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRunLogsArgs)(nil)).Elem()
}

// A collection of values returned by getRunLogs.
type GetRunLogsResultOutput struct{ *pulumi.OutputState }

func (GetRunLogsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRunLogsResult)(nil)).Elem()
}

func (o GetRunLogsResultOutput) ToGetRunLogsResultOutput() GetRunLogsResultOutput {
	return o
}

func (o GetRunLogsResultOutput) ToGetRunLogsResultOutputWithContext(ctx context.Context) GetRunLogsResultOutput {
	return o
}

func (o GetRunLogsResultOutput) Filters() GetRunLogsFilterArrayOutput {
	return o.ApplyT(func(v GetRunLogsResult) []GetRunLogsFilter { return v.Filters }).(GetRunLogsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRunLogsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRunLogsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetRunLogsResultOutput) RunId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRunLogsResult) string { return v.RunId }).(pulumi.StringOutput)
}

// The list of run_logs.
func (o GetRunLogsResultOutput) RunLogs() GetRunLogsRunLogArrayOutput {
	return o.ApplyT(func(v GetRunLogsResult) []GetRunLogsRunLog { return v.RunLogs }).(GetRunLogsRunLogArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRunLogsResultOutput{})
}